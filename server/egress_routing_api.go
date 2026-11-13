package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/egressroute"
)

func (s *Server) getEgressRouting(w http.ResponseWriter, r *http.Request) {
	if s.m.routing == nil {
		writeErr(w, 503, "出口路由尚未启动")
		return
	}
	writeJSON(w, 200, map[string]any{"config": s.m.routing.router.Config()})
}

func (s *Server) putEgressRouting(w http.ResponseWriter, r *http.Request) {
	if s.m.routing == nil {
		writeErr(w, 503, "出口路由尚未启动")
		return
	}
	var request struct {
		Config egressroute.Config `json:"config"`
	}
	if err := decode(r, &request); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.m.routing.configMu.Lock()
	defer s.m.routing.configMu.Unlock()
	cfg, err := validateRoutingConfig(request.Config)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	body, _ := json.Marshal(cfg)
	if err := s.m.pg.SetSetting(settingEgressRouting, string(body)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := s.m.routing.router.Update(cfg); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.m.routing.recordPolicyChange("target-rules-updated", "", "", "inherit")
	writeJSON(w, 200, map[string]any{"ok": true, "config": cfg})
}

func (s *Server) getEgressRoutingStatus(w http.ResponseWriter, r *http.Request) {
	if s.m.routing == nil {
		writeErr(w, 503, "出口路由尚未启动")
		return
	}
	tor := s.m.TorPoolStatus()
	running := 0
	for _, instance := range tor.Instances {
		if instance.Running && instance.CookieReady {
			running++
		}
	}
	writeJSON(w, 200, map[string]any{"status": map[string]any{
		"tor":             map[string]any{"ready": tor.Started && running == tor.Size && running > 0, "size": tor.Size, "running": running},
		"clash":           s.m.routing.clashStatus(r.Context()),
		"fallback_states": s.m.routing.router.Snapshot().States,
	}})
}

func (s *Server) getEgressRoutingAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.pg.Query(`SELECT detail FROM egress_route_events ORDER BY id DESC LIMIT 200`)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	events := []json.RawMessage{}
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		events = append(events, json.RawMessage(body))
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"events": events})
}

func (s *Server) routePlan(seed egressroute.Binding, target string) (EgressPlan, error) {
	rt := s.m.routing
	if _, ok := rt.platformAddress(&http.Request{URL: &url.URL{Scheme: "https", Host: net.JoinHostPort(target, "443")}}); ok {
		return EgressPlan{Mode: "direct", Provider: "direct", Reason: "platform-exception", ProxyURL: rt.proxyURL(seed, true), CACert: s.m.ProxyCACert()}, nil
	}
	b, err := rt.binding(seed)
	if err != nil {
		return EgressPlan{}, err
	}
	decision, err := rt.router.Select(b, target)
	if err != nil {
		return EgressPlan{}, err
	}
	return EgressPlan{Mode: string(decision.Provider), Provider: string(decision.Provider), ProxyURL: rt.proxyURL(seed, true), CACert: s.m.ProxyCACert(), IsTor: decision.Provider == egressroute.ProviderTor, RuleID: decision.RuleID, Reason: decision.Reason}, nil
}

func (s *Server) testEgressRouting(w http.ResponseWriter, r *http.Request) {
	if s.m.routing == nil {
		writeErr(w, 503, "出口路由尚未启动")
		return
	}
	var request struct {
		URL      string `json:"url"`
		TaskID   string `json:"task_id"`
		AgentKey string `json:"agent_key"`
		Mode     string `json:"mode"`
	}
	if err := decode(r, &request); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if request.URL == "" {
		request.URL = "https://check.torproject.org/api/ip"
	}
	u, err := url.Parse(request.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		writeErr(w, 400, "检测地址必须是有效的 HTTP/HTTPS URL")
		return
	}
	if request.Mode != "" && request.Mode != "inherit" && request.Mode != "tor" && request.Mode != "clash" {
		writeErr(w, 400, "检测出口需为 inherit/tor/clash")
		return
	}
	seed := egressroute.Binding{TaskID: request.TaskID, AgentKey: request.AgentKey, Mode: request.Mode}
	plan, err := s.routePlan(seed, u.Hostname())
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	probe := probeRoutingURL(ctx, plan, request.URL)
	if after, err := s.routePlan(seed, u.Hostname()); err == nil {
		plan = after
	}
	writeJSON(w, 200, map[string]any{"ok": probe.Error == "", "resolved": plan, "probe": probe})
}

func probeRoutingURL(ctx context.Context, plan EgressPlan, target string) egressProbe {
	client, err := egressProbeClient(plan)
	if err != nil {
		return egressProbe{Error: err.Error()}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return egressProbe{Error: err.Error()}
	}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return egressProbe{Error: err.Error()}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16384))
	if err != nil {
		return egressProbe{Error: err.Error()}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return egressProbe{Error: fmt.Sprintf("HTTP %d", response.StatusCode)}
	}
	var payload struct {
		IP    string `json:"IP"`
		IsTor bool   `json:"IsTor"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || strings.TrimSpace(payload.IP) == "" {
		return egressProbe{Error: "目标未返回出口检测 JSON；请使用 Tor 官方检测地址，或通过回连平台核验"}
	}
	return egressProbe{IP: payload.IP, IsTor: payload.IsTor, LatencyMS: time.Since(start).Milliseconds()}
}
