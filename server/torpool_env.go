package server

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

type torPoolSettingsStore interface {
	GetSetting(string) (string, bool, error)
	InsertSettingIfAbsent(string, string) (bool, error)
}

// bootstrapTorPoolEnv seeds deployment defaults once. Settings saved through the
// UI remain authoritative on later boots, including an explicit disabled pool.
func bootstrapTorPoolEnv(store torPoolSettingsStore, getenv func(string) string) error {
	type setting struct{ env, key, kind string }
	settings := []setting{
		{"ARTEX_TOR_POOL_ENABLED", settingTorPoolOn, "bool"},
		{"ARTEX_TOR_POOL_SIZE", settingTorPoolSize, "size"},
		{"ARTEX_TOR_POOL_SOCKS_BASE", settingTorPoolSocksBase, "port"},
		{"ARTEX_TOR_POOL_CONTROL_BASE", settingTorPoolControlBase, "port"},
		{"ARTEX_TOR_POOL_DIR", settingTorPoolDir, "dir"},
		{"ARTEX_TOR_POOL_BINARY", settingTorBinary, "binary"},
		{"ARTEX_TOR_POOL_UPSTREAM", settingTorPoolUpstream, "upstream"},
	}
	pending := make(map[string]string)
	effective := map[string]string{settingTorPoolSize: "5", settingTorPoolSocksBase: "19050", settingTorPoolControlBase: "19150"}
	for _, s := range settings {
		raw := getenv(s.env)
		if strings.ContainsAny(raw, "\r\n\x00") {
			return fmt.Errorf("%s: control characters are not allowed", s.env)
		}
		value := strings.TrimSpace(raw)
		if value != "" {
			var err error
			value, err = validateTorPoolEnv(s.kind, value)
			if err != nil {
				return fmt.Errorf("%s: %w", s.env, err)
			}
		}
		saved, exists, err := store.GetSetting(s.key)
		if err != nil {
			return fmt.Errorf("read Tor pool setting %s: %w", s.key, err)
		}
		if exists {
			effective[s.key] = saved
		} else if value != "" {
			pending[s.key] = value
			effective[s.key] = value
		}
	}
	// Check port ranges against saved settings as well, before writing anything.
	if len(pending) != 0 {
		size, err1 := strconv.Atoi(effective[settingTorPoolSize])
		socks, err2 := strconv.Atoi(effective[settingTorPoolSocksBase])
		control, err3 := strconv.Atoi(effective[settingTorPoolControlBase])
		if err1 != nil || err2 != nil || err3 != nil || size < 1 || size > 32 || socks < 1 || control < 1 || socks+size-1 > 65535 || control+size-1 > 65535 {
			return fmt.Errorf("Tor pool environment defaults conflict with an invalid saved size or port range")
		}
		if socks <= control+size-1 && control <= socks+size-1 {
			return fmt.Errorf("Tor pool SOCKS and control port ranges overlap")
		}
	}
	for _, s := range settings {
		if value, ok := pending[s.key]; ok {
			if _, err := store.InsertSettingIfAbsent(s.key, value); err != nil {
				return fmt.Errorf("initialize Tor pool setting %s: %w", s.key, err)
			}
		}
	}
	return nil
}

func validateTorPoolEnv(kind, value string) (string, error) {
	switch kind {
	case "bool":
		v, err := strconv.ParseBool(value)
		if err != nil {
			return "", fmt.Errorf("expected true or false")
		}
		return strconv.FormatBool(v), nil
	case "size", "port":
		v, err := strconv.Atoi(value)
		max := 65535
		if kind == "size" {
			max = 32
		}
		if err != nil || v < 1 || v > max {
			return "", fmt.Errorf("expected an integer between 1 and %d", max)
		}
		return strconv.Itoa(v), nil
	case "dir":
		if !filepath.IsAbs(value) {
			return "", fmt.Errorf("expected an absolute persistent directory")
		}
		return filepath.Clean(value), nil
	case "binary":
		if !filepath.IsAbs(value) && (filepath.Base(value) != value || strings.ContainsFunc(value, unicode.IsSpace)) {
			return "", fmt.Errorf("expected an absolute executable path or command name")
		}
	case "upstream":
		// Tor expects [user:password@]host:port, without a URL scheme.
		address := value
		if at := strings.LastIndex(address, "@"); at >= 0 {
			if !strings.Contains(address[:at], ":") {
				return "", fmt.Errorf("upstream credentials must use user:password@host:port")
			}
			address = address[at+1:]
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || host == "" || strings.ContainsAny(host, "/@") || strings.ContainsFunc(value, unicode.IsSpace) {
			return "", fmt.Errorf("expected [user:password@]host:port, without a URL scheme")
		}
		if _, err := validateTorPoolEnv("port", port); err != nil {
			return "", fmt.Errorf("invalid upstream port")
		}
	}
	return value, nil
}
