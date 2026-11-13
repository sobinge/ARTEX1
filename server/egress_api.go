package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Autumn-27/artex/egressroute"
	"github.com/Autumn-27/artex/tor"
	"github.com/Autumn-27/artex/traffic"
)

// egressProbe is the result of a real request through the agent's egress.
type egressProbe struct {
	IP        string `json:"ip"`
	Country   string `json:"country"`
	IsTor     bool   `json:"is_tor"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// probeEgress obtains the exit IP and Tor status in one official check request.
func probeEgress(ctx context.Context, plan EgressPlan) egressProbe {
	return probeRoutingURL(ctx, plan, "https://check.torproject.org/api/ip")
}

func egressProbeClient(plan EgressPlan) (*http.Client, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	u, err := traffic.ValidateProxyURL(plan.ProxyURL)
	if err != nil || u == nil {
		return nil, fmt.Errorf("出口检测必须使用有效代理；不会回退直连")
	}
	transport.Proxy = http.ProxyURL(u)
	if plan.CACert != "" {
		pem, err := os.ReadFile(plan.CACert)
		if err != nil {
			return nil, fmt.Errorf("读取记录代理 CA 失败: %w", err)
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("记录代理 CA 无效")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

func getBody(ctx context.Context, c *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", &httpError{code: resp.StatusCode}
	}
	return string(b), nil
}

type httpError struct{ code int }

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

// getAgentEgress reports the effective egress for one agent plus a live probe.
func (s *Server) getAgentEgress(w http.ResponseWriter, r *http.Request) {
	pg, a, ok := s.agentByKey(w, r)
	if !ok {
		return
	}
	_ = pg
	plan, err := s.resolveEgress(a, "")
	if s.m.routing != nil {
		plan, err = s.routePlan(egressroute.Binding{AgentKey: a.Key}, "check.torproject.org")
	}
	resp := map[string]any{
		"agent_key": a.Key,
		"mode":      a.EgressMode,
		"resolved":  plan,
	}
	if err != nil {
		resp["error"] = err.Error()
		resp["ok"] = false
		writeJSON(w, 200, resp)
		return
	}
	resp["ok"] = true
	writeJSON(w, 200, resp)
}

// testAgentEgress probes the egress without executing any agent.
func (s *Server) testAgentEgress(w http.ResponseWriter, r *http.Request) {
	_, a, ok := s.agentByKey(w, r)
	if !ok {
		return
	}
	plan, err := s.resolveEgress(a, "")
	if s.m.routing != nil {
		plan, err = s.routePlan(egressroute.Binding{AgentKey: a.Key}, "check.torproject.org")
	}
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	p := probeEgress(ctx, plan)
	writeJSON(w, 200, map[string]any{"ok": p.Error == "", "probe": p, "resolved": plan})
}

// newNym rotates the Tor circuits of the daemon serving this agent.
//
// Pooled mode (tor_pool_enabled): only that agent's slot is rotated, so other
// agents keep their exits — the whole point of the pool. Legacy mode: one shared
// daemon, so the rotation is process-wide and the UI says so.
func (s *Server) newNym(w http.ResponseWriter, r *http.Request) {
	_, a, ok := s.agentByKey(w, r)
	if !ok {
		return
	}
	if pool := s.m.TorPool(); pool != nil && pool.Started() {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		inst, err := pool.NewNym(ctx, a.Key, a.EgressTorInstance)
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "scope": "instance", "instance": inst.ID})
		return
	}
	addr := s.m.TorControlAddr()
	if addr == "" {
		writeErr(w, 400, "未配置 tor_control_addr，无法换电路")
		return
	}
	c := &tor.Client{Addr: addr, CookiePath: s.m.TorCookiePath()}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := c.NewNym(ctx); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "scope": "daemon"})
}

// listAgentEgressRuns returns the audit trail for one agent.
func (s *Server) listAgentEgressRuns(w http.ResponseWriter, r *http.Request) {
	pg, a, ok := s.agentByKey(w, r)
	if !ok {
		return
	}
	runs, err := pg.ListEgressRuns(a.Key, 100)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"runs": runs})
}
