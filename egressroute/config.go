// Package egressroute selects and enforces target proxy routes. It never opens
// a direct connection to a target, including when a proxy or rule is invalid.
package egressroute

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Provider string

const (
	ProviderTor   Provider = "tor"
	ProviderClash Provider = "clash"
	ProviderProxy Provider = "proxy" // explicit legacy proxy, never assumed to be Tor
)

type Binding struct {
	TaskID   string `json:"task_id,omitempty"`
	AgentKey string `json:"agent_key,omitempty"`
	Mode     string `json:"mode,omitempty"`
	ProxyURL string `json:"proxy_url,omitempty"`
}

type Rule struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"` // domain, suffix, ip, cidr
	Value         string   `json:"value"`
	Provider      Provider `json:"provider"`
	AllowFallback bool     `json:"allow_fallback"`
	Enabled       bool     `json:"enabled"`
}

type FallbackConfig struct {
	Enabled          bool `json:"enabled"`
	FailureThreshold int  `json:"failure_threshold"`
	CooldownSeconds  int  `json:"cooldown_seconds"`
}

type Config struct {
	Rules      []Rule         `json:"rules"`
	Fallback   FallbackConfig `json:"fallback"`
	ClashProxy string         `json:"clash_proxy,omitempty"`
}

func DefaultConfig() Config {
	return Config{Rules: []Rule{}, Fallback: FallbackConfig{FailureThreshold: 3, CooldownSeconds: 300}, ClashProxy: "http://127.0.0.1:7890"}
}

// Validate normalizes a copy and rejects ambiguous rules before publication.
func (c Config) Validate() (Config, error) {
	c.Rules = append([]Rule{}, c.Rules...)
	if len(c.Rules) > 1000 {
		return Config{}, fmt.Errorf("at most 1000 target egress rules are supported")
	}
	if c.Fallback.FailureThreshold == 0 {
		c.Fallback.FailureThreshold = 3
	}
	if c.Fallback.CooldownSeconds == 0 {
		c.Fallback.CooldownSeconds = 300
	}
	if c.Fallback.FailureThreshold < 1 || c.Fallback.FailureThreshold > 100 {
		return Config{}, fmt.Errorf("failure_threshold must be between 1 and 100")
	}
	if c.Fallback.CooldownSeconds < 1 || c.Fallback.CooldownSeconds > 86400 {
		return Config{}, fmt.Errorf("cooldown_seconds must be between 1 and 86400")
	}
	c.ClashProxy = strings.TrimSpace(c.ClashProxy)
	if c.ClashProxy != "" {
		if _, err := proxyURL(c.ClashProxy); err != nil {
			return Config{}, fmt.Errorf("clash_proxy: %w", err)
		}
	}
	ids := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		r.ID, r.Type, r.Value = strings.TrimSpace(r.ID), strings.ToLower(strings.TrimSpace(r.Type)), strings.TrimSpace(r.Value)
		if r.ID == "" || len(r.ID) > 100 || strings.ContainsAny(r.ID, "\r\n\x00") || ids[r.ID] {
			return Config{}, fmt.Errorf("rule %d needs a unique ID of at most 100 characters", i+1)
		}
		ids[r.ID] = true
		if r.Provider != ProviderTor && r.Provider != ProviderClash {
			return Config{}, fmt.Errorf("rule %s provider must be tor or clash", r.ID)
		}
		if r.AllowFallback && r.Provider != ProviderTor {
			return Config{}, fmt.Errorf("rule %s: fallback is only valid for a Tor primary", r.ID)
		}
		switch r.Type {
		case "domain", "suffix":
			r.Value = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(r.Value, ".")), ".")
			if !validDomain(r.Value) {
				return Config{}, fmt.Errorf("rule %s has an invalid domain", r.ID)
			}
		case "ip":
			address, err := netip.ParseAddr(r.Value)
			if err != nil {
				return Config{}, fmt.Errorf("rule %s has an invalid IP", r.ID)
			}
			r.Value = address.Unmap().String()
		case "cidr":
			prefix, err := netip.ParsePrefix(r.Value)
			if err != nil {
				return Config{}, fmt.Errorf("rule %s has an invalid CIDR", r.ID)
			}
			r.Value = prefix.Masked().String()
		default:
			return Config{}, fmt.Errorf("rule %s type must be domain, suffix, ip or cidr", r.ID)
		}
	}
	return c, nil
}

func validDomain(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /:@?#\\\r\n\t\x00") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func normalizeHost(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(value, "."))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = strings.TrimSuffix(parsed, ".")
	}
	host = strings.Trim(host, "[]")
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String(), nil
	}
	if !validDomain(host) {
		return "", fmt.Errorf("invalid target host")
	}
	return host, nil
}

func matches(rule Rule, host string) bool {
	switch rule.Type {
	case "domain":
		return host == rule.Value
	case "suffix":
		return host == rule.Value || strings.HasSuffix(host, "."+rule.Value)
	case "ip":
		return host == rule.Value
	case "cidr":
		address, err := netip.ParseAddr(host)
		prefix, _ := netip.ParsePrefix(rule.Value)
		return err == nil && prefix.Contains(address)
	}
	return false
}

func proxyURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("proxy unavailable; direct fallback is forbidden")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("proxy scheme must be http, https, socks5 or socks5h")
	}
	if u.Hostname() == "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid proxy address")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid proxy port")
		}
	}
	return u, nil
}

func proxyHint(u *url.URL) string {
	copy := *u
	if copy.User != nil {
		copy.User = url.User("***")
	}
	return copy.String()
}
