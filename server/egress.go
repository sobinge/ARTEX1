package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/torpool"
)

// EgressClass classifies what a piece of traffic is for. The class — not the
// agent — decides the required egress, so a scanner can never inherit a
// direct-dial default just because it was configured loosely.
type EgressClass string

const (
	// ClassTargetProbe covers anything that touches the target: subdomain
	// enumeration, fingerprinting, directory/port probing, crawling.
	// MUST be anonymous; never falls back to a direct connection.
	ClassTargetProbe EgressClass = "target-probe"
	// ClassTargetExploit covers exploitation and post-exploitation requests.
	// Anonymous by default, waivable per task with an explicit record.
	ClassTargetExploit EgressClass = "target-exploit"
	// ClassIntelQuery covers third-party intel APIs (FOFA, Shodan, Quake…).
	// Allowed to use the real IP: those platforms block Tor exits, and the
	// query is not aimed at the target.
	ClassIntelQuery EgressClass = "intel-query"
	// ClassPlatformSelf covers updates, tool downloads and mirror pulls.
	ClassPlatformSelf EgressClass = "platform-self"
	// ClassNotify covers webhook/alert delivery.
	ClassNotify EgressClass = "notify"
)

// Default intel allow-list. Matched as domain suffixes so subdomains work.
var defaultIntelHosts = []string{
	"fofa.info",
	"api.shodan.io",
	"quake.360.cn",
}

// EgressPlan is the resolved egress for one agent run.
type EgressPlan struct {
	Mode        string `json:"mode"`      // direct | proxy | tor
	ProxyURL    string `json:"proxy_url"` // what SetProxy receives; socks5h for tor
	CACert      string `json:"ca_cert,omitempty"`
	IsTor       bool   `json:"is_tor"`
	CircuitUser string `json:"circuit_user,omitempty"`
	ExitCountry string `json:"exit_country,omitempty"`
	// TorInstance is the torpool slot serving this agent (1-based); 0 means the
	// single shared daemon. It is what makes NEWNYM per-agent instead of global.
	TorInstance int `json:"tor_instance,omitempty"`
}

// Anonymous reports whether this plan hides the platform's real IP.
func (p EgressPlan) Anonymous() bool { return p.IsTor || p.Mode == "proxy" }

// EgressError describes a refused egress. The UI surfaces it verbatim; it is
// deliberately explicit about NOT falling back to a direct connection.
type EgressError struct {
	Class  EgressClass
	Agent  string
	Reason string
}

func (e *EgressError) Error() string {
	return fmt.Sprintf("出口策略拒绝执行(%s, agent=%s): %s；不会回退直连",
		e.Class, e.Agent, e.Reason)
}

// torSocksURL builds the SOCKS URL handed to agents. The SOCKS username doubles
// as the Tor circuit-isolation key (IsolateSOCKSAuth): different usernames get
// different circuits, and Tor accepts any credentials.
func torSocksURL(base, circuitUser string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	if !strings.Contains(base, "://") {
		base = "socks5h://" + base
	}
	if i := strings.Index(base, "://"); i >= 0 {
		scheme, rest := base[:i], base[i+3:]
		if !strings.EqualFold(scheme, "socks5h") {
			scheme = "socks5h"
		}
		if circuitUser != "" && !strings.Contains(rest, "@") {
			rest = circuitUser + ":x@" + rest
		}
		return scheme + "://" + rest
	}
	return base
}

// canonicalEgressAgent maps a runtime slot label to the agent row it runs under.
//
// Worker slots are named "work#1", "work#2"… at runtime, but the egress policy
// lives on the "worker" agent row. Passing the slot name straight to the audit
// made GetAgentByKey fail → the row was recorded as refused even though the run
// was actually going through Tor.
func canonicalEgressAgent(label string) string {
	l := strings.TrimSpace(label)
	if strings.HasPrefix(l, "work#") {
		return "worker"
	}
	if strings.HasPrefix(l, "plan#") {
		return "planner"
	}
	return l
}

// agentEgress looks up an agent and resolves its egress. A missing agent row
// falls back to the system default (still fail-closed when strict).
func (s *Server) agentEgress(key string, taskID string) (EgressPlan, error) {
	var a *db.Agent
	if s.m.pg != nil {
		if got, err := s.m.pg.GetAgentByKey(key); err == nil {
			a = got
		}
	}
	return s.resolveEgress(a, taskID)
}

// blackholeProxy is what agents get when fail-closed trips: a SOCKS endpoint that
// never answers. Routing target traffic here is strictly better than returning ""
// (which means "direct") — a misconfiguration must never fall back to the real IP.
const blackholeProxy = "socks5h://127.0.0.1:1"

// egressProxyFor returns the proxy address plus CA for SetProxy.
//
// Capture on: agents must point at the recording MITM (that is where traffic is
// captured); the MITM's own upstream is the global egress. Per-agent Tor is not
// available in that mode — a documented limitation, not an oversight.
//
// Capture off: the resolved per-agent egress is injected directly; an unresolved
// strict egress becomes a black hole rather than a direct connection.
func (s *Server) egressProxyFor(key, taskID string) (string, string) {
	if s.m.TrafficEnabled() {
		return s.m.ProxyAddr(), s.m.ProxyCACert()
	}
	plan, err := s.agentEgress(key, taskID)
	if err != nil {
		return blackholeProxy, ""
	}
	if plan.Mode == "direct" {
		return "", ""
	}
	return plan.ProxyURL, ""
}

// torEgressFor reports whether this agent's traffic goes through Tor, plus the
// exit country, for prompt injection.
func (s *Server) torEgressFor(key, taskID string) (bool, string) {
	if s.m.TrafficEnabled() {
		// Recording MITM: its upstream is the global proxy. Treat a SOCKS
		// upstream as Tor for prompt purposes.
		gp := strings.ToLower(strings.TrimSpace(s.m.GlobalProxy()))
		return strings.HasPrefix(gp, "socks5"), ""
	}
	plan, err := s.agentEgress(key, taskID)
	if err != nil {
		return false, ""
	}
	return plan.IsTor, plan.ExitCountry
}

// egressBinding is the ChatAgent resolver: per-agent address + Tor flag.
func (s *Server) egressBinding(agentKey string) (string, string, bool, string) {
	if s.m.TrafficEnabled() {
		tor, country := s.torEgressFor(agentKey, "")
		return s.m.ProxyAddr(), s.m.ProxyCACert(), tor, country
	}
	plan, err := s.agentEgress(agentKey, "")
	if err != nil {
		return blackholeProxy, "", false, ""
	}
	if plan.Mode == "direct" {
		return "", "", false, ""
	}
	return plan.ProxyURL, "", plan.IsTor, plan.ExitCountry
}

// resolveEgress picks the egress for one agent. Priority:
//
//	agent.egress_mode → system global proxy → (strict? error : direct)
//
// A strict system never silently falls back to direct: that is the whole point
// of the setting (fail-closed).
func (s *Server) resolveEgress(a *db.Agent, taskID string) (EgressPlan, error) {
	mode, proxy, country, circuitKey := "", "", "", ""
	agentKey := ""
	if a != nil {
		agentKey = a.Key
		mode, proxy, country, circuitKey = a.EgressMode, a.EgressProxy, a.TorExitCountry, a.TorCircuitKey
	}
	if mode == "" || mode == "inherit" {
		if gp := strings.TrimSpace(s.m.GlobalProxy()); gp != "" {
			plan := EgressPlan{Mode: "proxy", ProxyURL: gp}
			if strings.HasPrefix(strings.ToLower(gp), "socks5") {
				plan.Mode = "tor"
				plan.IsTor = true
				plan.ProxyURL = torSocksURL(gp, "")
			}
			return plan, nil
		}
		if s.m.EgressStrict() {
			return EgressPlan{}, &EgressError{
				Class:  ClassTargetProbe,
				Agent:  agentKey,
				Reason: "未配置匿名出口（egress_strict 已开启）",
			}
		}
		return EgressPlan{Mode: "direct"}, nil
	}

	switch mode {
	case "direct":
		// Explicit per-agent choice. Still refused for target-probe when the
		// system is strict: "I picked direct" is not a reason to leak the IP.
		if s.m.EgressStrict() {
			return EgressPlan{}, &EgressError{
				Class:  ClassTargetProbe,
				Agent:  agentKey,
				Reason: "agent 显式选择直连，但全局禁止目标流量走真实 IP",
			}
		}
		return EgressPlan{Mode: "direct"}, nil
	case "proxy":
		if strings.TrimSpace(proxy) == "" {
			return EgressPlan{}, &EgressError{Class: ClassTargetProbe, Agent: agentKey, Reason: "egress_mode=proxy 但未填代理地址"}
		}
		return EgressPlan{Mode: "proxy", ProxyURL: proxy}, nil
	case "tor":
		// Pooled mode: the agent's slot decides the SOCKS port, so both the exit
		// and SIGNAL NEWNYM are scoped to that agent only.
		var inst *torpool.Instance
		if pool := s.m.TorPool(); pool != nil {
			override := 0
			if a != nil {
				override = a.EgressTorInstance
			}
			inst = pool.For(agentKey, override)
		}
		base := strings.TrimSpace(s.m.TorSocksAddr())
		if inst != nil {
			base = "socks5h://" + inst.SocksAddr
		} else if base == "" {
			base = strings.TrimSpace(s.m.GlobalProxy())
		}
		if base == "" {
			return EgressPlan{}, &EgressError{Class: ClassTargetProbe, Agent: agentKey, Reason: "egress_mode=tor 但未配置 Tor SOCKS 地址"}
		}
		user := ""
		switch circuitKey {
		case "agent":
			user = "agent-" + agentKey
		case "", "task":
			if taskID != "" {
				user = "task-" + taskID
			}
		}
		plan := EgressPlan{
			Mode: "tor", ProxyURL: torSocksURL(base, user),
			IsTor: true, CircuitUser: user, ExitCountry: country,
		}
		if inst != nil {
			plan.TorInstance = inst.ID
		}
		return plan, nil
	default:
		return EgressPlan{}, &EgressError{Class: ClassTargetProbe, Agent: agentKey, Reason: "未知 egress_mode: " + mode}
	}
}

// checkToolEgress is the execution-layer gate. It refuses a tool call when:
//   - the system is strict and no anonymous egress is configured (fail-closed), or
//   - the tool needs UDP and the resolved egress is Tor (Tor carries no UDP).
//
// Prompt text can be ignored by a model; this check cannot.
func (s *Server) checkToolEgress(t *db.Tool) error {
	if t == nil {
		return nil
	}
	class := t.EgressClass
	if class == "" {
		class = string(ClassTargetProbe)
	}
	if class != string(ClassTargetProbe) && class != string(ClassTargetExploit) {
		return nil // intel / platform / notify classes are allowed to dial direct
	}
	plan, err := s.agentEgress("", "")
	if err != nil {
		return err
	}
	if t.NeedsUDP && plan.IsTor {
		return &EgressError{Class: EgressClass(class), Agent: t.Key,
			Reason: "该工具需要 UDP，Tor 出口不承载 UDP"}
	}
	return nil
}

// redactProxyHint keeps a proxy address usable in audit output without leaking
// credentials: user:pass@ is replaced by ***@.
func redactProxyHint(raw string) string {
	raw = strings.TrimSpace(raw)
	at := strings.LastIndex(raw, "@")
	scheme := ""
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, rest = raw[:i+3], raw[i+3:]
	}
	if at < 0 {
		return scheme + rest
	}
	if j := strings.LastIndex(rest, "@"); j >= 0 {
		rest = rest[j+1:]
	}
	return scheme + "***@" + rest
}

// beginEgressAudit opens an audit row for one work run. The returned finisher
// closes it; the exit IP is probed in the background so a slow Tor circuit never
// delays the run's own completion.
func (s *Server) beginEgressAudit(taskID, agentKey string) func(error) {
	if s.m.pg == nil {
		return nil
	}
	var agent *db.Agent
	if got, err := s.m.pg.GetAgentByKey(agentKey); err == nil {
		agent = got
	}
	plan, err := s.resolveEgress(agent, taskID)
	if err != nil {
		// Refused egress is still worth recording: it is the evidence that the
		// platform refused rather than dialed direct.
		id, ierr := s.m.pg.StartEgressRun(agentKey, "refused", err.Error(), &taskID, nil)
		if ierr != nil {
			return nil
		}
		return func(error) { _ = s.m.pg.FinishEgressRun(id, "", false, "") }
	}
	id, ierr := s.m.pg.StartEgressRun(agentKey, plan.Mode, redactProxyHint(plan.ProxyURL), &taskID, nil)
	if ierr != nil {
		return nil
	}
	mode, user := plan.Mode, plan.CircuitUser
	return func(runErr error) {
		if mode == "direct" {
			_ = s.m.pg.FinishEgressRun(id, "", false, user)
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			p := probeEgress(ctx, plan)
			_ = s.m.pg.FinishEgressRun(id, p.IP, p.IsTor, user)
		}()
	}
}
