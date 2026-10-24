package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/tor"
)

// egressProbe is the result of a real request through the agent's egress.
type egressProbe struct {
	IP        string `json:"ip"`
	Country   string `json:"country"`
	IsTor     bool   `json:"is_tor"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// probeEgress makes two requests through plan: one for the exit IP, one to the
// Tor project's check endpoint. Both go through the resolved proxy so the numbers
// describe the egress the agent will actually use.
func probeEgress(ctx context.Context, plan EgressPlan) egressProbe {
	client := &http.Client{Timeout: 25 * time.Second}
	if plan.ProxyURL != "" {
		u, err := url.Parse(plan.ProxyURL)
		if err != nil {
			return egressProbe{Error: "代理地址无效: " + err.Error()}
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(u)}
	}
	start := time.Now()
	ip, err := getBody(ctx, client, "https://api.ipify.org")
	if err != nil {
		return egressProbe{Error: err.Error()}
	}
	out := egressProbe{IP: strings.TrimSpace(ip), LatencyMS: time.Since(start).Milliseconds()}
	if body, err := getBody(ctx, client, "https://check.torproject.org/api/ip"); err == nil {
		var r struct {
			IsTor bool   `json:"IsTor"`
			IP    string `json:"IP"`
		}
		if json.Unmarshal([]byte(body), &r) == nil {
			out.IsTor = r.IsTor
		}
	}
	if body, err := getBody(ctx, client, "http://ip-api.com/json/"+out.IP+"?fields=country,countryCode"); err == nil {
		var geo struct {
			Country string `json:"country"`
		}
		if json.Unmarshal([]byte(body), &geo) == nil {
			out.Country = geo.Country
		}
	}
	return out
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
