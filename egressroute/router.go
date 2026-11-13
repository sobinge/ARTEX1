package egressroute

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Resolver func(context.Context, Binding, Provider) (string, error)
type AuditFunc func(AuditEvent)

type Decision struct {
	Provider      Provider  `json:"provider"`
	Primary       Provider  `json:"primary"`
	RuleID        string    `json:"rule_id,omitempty"`
	Reason        string    `json:"reason"`
	AllowFallback bool      `json:"allow_fallback"`
	InFallback    bool      `json:"in_fallback"`
	Target        string    `json:"target"`
	Failures      int       `json:"failures"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
	generation    uint64
}

type AuditEvent struct {
	At            time.Time `json:"at"`
	TaskID        string    `json:"task_id,omitempty"`
	AgentKey      string    `json:"agent_key,omitempty"`
	Host          string    `json:"host"`
	Method        string    `json:"method"`
	Provider      Provider  `json:"provider"`
	Primary       Provider  `json:"primary"`
	RuleID        string    `json:"rule_id,omitempty"`
	Reason        string    `json:"reason"`
	Success       bool      `json:"success"`
	Error         string    `json:"error,omitempty"`
	DurationMS    int64     `json:"duration_ms"`
	ProxyHint     string    `json:"proxy_hint,omitempty"`
	Failures      int       `json:"failures"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
}

type State struct {
	TaskID        string    `json:"task_id,omitempty"`
	AgentKey      string    `json:"agent_key,omitempty"`
	Host          string    `json:"host"`
	Failures      int       `json:"failures"`
	FallbackUntil time.Time `json:"fallback_until,omitempty"`
	lastUsed      time.Time
}

type Snapshot struct {
	States []State `json:"states"`
}

type stateKey struct{ task, agent, host string }

type Router struct {
	mu         sync.Mutex
	config     Config
	generation uint64
	states     map[stateKey]State
	transports map[string]*http.Transport
	resolver   Resolver
	audit      AuditFunc
	now        func() time.Time
}

func New(config Config, resolver Resolver, audit AuditFunc) (*Router, error) {
	cfg, err := config.Validate()
	if err != nil {
		return nil, err
	}
	if resolver == nil {
		return nil, fmt.Errorf("egress resolver is required; direct fallback is forbidden")
	}
	return &Router{config: cfg, generation: 1, states: map[stateKey]State{}, transports: map[string]*http.Transport{}, resolver: resolver, audit: audit, now: time.Now}, nil
}

func (r *Router) Update(config Config) error {
	cfg, err := config.Validate()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.config = cfg
	r.generation++
	r.states = map[stateKey]State{}
	for _, transport := range r.transports {
		transport.CloseIdleConnections()
	}
	r.transports = map[string]*http.Transport{}
	r.mu.Unlock()
	return nil
}

func (r *Router) Config() Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.config
	c.Rules = append([]Rule{}, c.Rules...)
	return c
}

func (r *Router) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := Snapshot{States: []State{}}
	for _, state := range r.states {
		out.States = append(out.States, state)
	}
	return out
}

// Select does not resolve the target locally. Host rules match the requested
// domain; IP/CIDR rules match literal IP destinations only.
func (r *Router) Select(binding Binding, target string) (Decision, error) {
	host, err := normalizeHost(target)
	if err != nil {
		return Decision{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	decision := Decision{Provider: ProviderTor, Primary: ProviderTor, Reason: "default-tor", Target: host, generation: r.generation}
	switch mode := strings.ToLower(strings.TrimSpace(binding.Mode)); mode {
	case "", "inherit":
	case "tor", "clash", "proxy":
		decision.Provider, decision.Primary = Provider(mode), Provider(mode)
		decision.Reason = "explicit-" + mode
		return decision, nil // Explicit Tor is never silently relaxed by a target rule.
	default:
		return Decision{}, fmt.Errorf("unsupported egress mode %q; direct fallback is forbidden", mode)
	}
	for _, rule := range r.config.Rules {
		if !rule.Enabled || !matches(rule, host) {
			continue
		}
		decision.Provider, decision.Primary = rule.Provider, rule.Provider
		decision.RuleID, decision.Reason = rule.ID, "target-rule"
		decision.AllowFallback = rule.Provider == ProviderTor && rule.AllowFallback && r.config.Fallback.Enabled
		break
	}
	if !decision.AllowFallback {
		return decision, nil
	}
	key := stateKey{binding.TaskID, binding.AgentKey, host}
	state, exists := r.states[key]
	if exists && !state.FallbackUntil.IsZero() && !r.now().Before(state.FallbackUntil) {
		delete(r.states, key)
		return decision, nil // Cooldown expiry is a fresh Tor trial for new traffic.
	}
	decision.Failures = state.Failures
	if exists && !state.FallbackUntil.IsZero() {
		decision.Provider, decision.InFallback = ProviderClash, true
		decision.Reason, decision.CooldownUntil = "tor-fallback-cooldown", state.FallbackUntil
	}
	return decision, nil
}

// result records one actual attempt, not a speculative route selection. A
// failed POST may affect subsequent requests, but this method never replays it.
func (r *Router) result(binding Binding, decision Decision, method string, started time.Time, hint string, err error) Decision {
	r.mu.Lock()
	if decision.generation == r.generation && decision.AllowFallback && decision.Provider == ProviderTor {
		key := stateKey{binding.TaskID, binding.AgentKey, decision.Target}
		if err == nil {
			delete(r.states, key)
			decision.Failures = 0
		} else {
			if len(r.states) >= 10000 {
				// A bounded table prevents arbitrary target names retaining state forever.
				var oldest stateKey
				var oldestAt time.Time
				for k, state := range r.states {
					if oldestAt.IsZero() || state.lastUsed.Before(oldestAt) {
						oldest, oldestAt = k, state.lastUsed
					}
				}
				delete(r.states, oldest)
			}
			state := r.states[key]
			state.TaskID, state.AgentKey, state.Host = binding.TaskID, binding.AgentKey, decision.Target
			state.Failures++
			state.lastUsed = r.now()
			if state.Failures >= r.config.Fallback.FailureThreshold {
				state.FallbackUntil = r.now().Add(time.Duration(r.config.Fallback.CooldownSeconds) * time.Second)
			}
			r.states[key] = state
			decision.Failures, decision.CooldownUntil = state.Failures, state.FallbackUntil
		}
	}
	r.mu.Unlock()
	if r.audit != nil {
		event := AuditEvent{At: r.now().UTC(), TaskID: binding.TaskID, AgentKey: binding.AgentKey,
			Host: decision.Target, Method: method, Provider: decision.Provider, Primary: decision.Primary,
			RuleID: decision.RuleID, Reason: decision.Reason, Success: err == nil,
			DurationMS: time.Since(started).Milliseconds(), ProxyHint: hint, Failures: decision.Failures,
			CooldownUntil: decision.CooldownUntil}
		if err != nil {
			event.Error = redactError(err)
		}
		r.audit(event)
	}
	return decision
}

func (r *Router) fallback(decision Decision) (Decision, bool) {
	if !decision.AllowFallback || decision.Provider != ProviderTor || decision.CooldownUntil.IsZero() {
		return Decision{}, false
	}
	decision.Provider, decision.InFallback = ProviderClash, true
	decision.Reason = "tor-failure-threshold"
	return decision, true
}

func safeMethod(method string) bool {
	// Restrict automatic replay to the two methods whose target actions should
	// be read-only. Idempotent PUT/DELETE are intentionally not replayed either.
	return method == http.MethodGet || method == http.MethodHead
}

var userinfoPattern = regexp.MustCompile(`(?i)(https?|socks5h?)://[^\s/@]+@`)

func redactError(err error) string {
	message := userinfoPattern.ReplaceAllString(err.Error(), "$1://***@")
	if len(message) > 1500 {
		message = message[:1500]
	}
	return message
}
