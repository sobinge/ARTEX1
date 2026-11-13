package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/egressroute"
	actool "github.com/Autumn-27/norma/tool"
)

func TestEgressToolGuardRejectsUncontrolledRoutes(t *testing.T) {
	clashRule := egressroute.Rule{ID: "clash-target", Type: "domain", Value: "example.com", Provider: egressroute.ProviderClash, Enabled: true}
	fallbackRule := egressroute.Rule{ID: "backup-target", Type: "domain", Value: "example.com", Provider: egressroute.ProviderTor, Enabled: true, AllowFallback: true}
	tests := []struct {
		name, mode string
		rules      []egressroute.Rule
		fallback   bool
		wantError  bool
	}{
		{"default Tor", "", nil, false, false},
		{"explicit Tor overrides target rule", "tor", []egressroute.Rule{clashRule}, true, false},
		{"explicit Clash", "clash", nil, false, true},
		{"explicit proxy", "proxy", nil, false, true},
		{"inherited Clash target", "inherit", []egressroute.Rule{clashRule}, false, true},
		{"disabled Clash target", "", []egressroute.Rule{{ID: "off", Provider: egressroute.ProviderClash}}, false, false},
		{"backup is off", "", []egressroute.Rule{fallbackRule}, false, false},
		{"backup is active", "", []egressroute.Rule{fallbackRule}, true, true},
		{"no target allows backup", "", nil, true, false},
		{"direct refused", "direct", nil, false, true},
		{"invalid mode refused", "invalid", nil, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := egressroute.DefaultConfig()
			cfg.Rules, cfg.Fallback.Enabled = tc.rules, tc.fallback
			for _, tool := range []struct {
				name string
				row  *db.Tool
			}{
				{"Bash", nil}, {"shell_open", nil},
				{"scanner", &db.Tool{Kind: "command"}}, {"python_probe", &db.Tool{Kind: "script"}},
			} {
				err := validateToolEgress(egressroute.Binding{Mode: tc.mode}, cfg, tool.name, tool.row)
				if (err != nil) != tc.wantError {
					t.Errorf("%s: error=%v, wantError=%v", tool.name, err, tc.wantError)
				}
			}
		})
	}
	cfg := egressroute.DefaultConfig()
	if err := validateToolEgress(egressroute.Binding{Mode: "clash"}, cfg, "WebFetch", nil); err != nil {
		t.Fatalf("controlled HTTP tool was denied: %v", err)
	}
	if err := validateToolEgress(egressroute.Binding{Mode: "tor"}, cfg, "udp_probe", &db.Tool{NeedsUDP: true}); err == nil {
		t.Fatal("UDP tool was allowed through a TCP-only gateway")
	}
}

func TestEgressToolMCPExplicitTorCannotUseSharedProxyContext(t *testing.T) {
	cfg := egressroute.DefaultConfig()
	cfg.Rules = []egressroute.Rule{{ID: "clash", Type: "domain", Value: "example.com", Provider: egressroute.ProviderClash, Enabled: true}}
	for _, binding := range []egressroute.Binding{{Mode: "tor"}, {Mode: "clash"}, {}} {
		if err := validateToolEgress(binding, cfg, "mcp__browser__navigate", nil); err == nil || !strings.Contains(err.Error(), "受控适配") {
			t.Fatalf("MCP without a routing adapter must be refused for %+v: %v", binding, err)
		}
	}
	if err := validateToolEgress(egressroute.Binding{Mode: "tor"}, egressroute.DefaultConfig(), "mcp__remote__fetch", nil); err == nil {
		t.Fatal("unknown remote MCP was allowed without a controlled adapter")
	}
}

func TestEgressToolGuardCarriesRunContextAndStopsDelegation(t *testing.T) {
	ri := agent.RunInfo{TaskID: 37, IntentID: 5}
	assemblyCtx := agent.WithRunInfo(context.Background(), ri)
	tc := &actool.ToolContext{WorkingDir: t.TempDir()}
	var calls int
	base := actool.Build(actool.Spec{Name: "controlled_http", Run: func(ctx context.Context, _ json.RawMessage, gotTC *actool.ToolContext) (actool.Result, error) {
		calls++
		if got := toolEgressSeed(ctx, "", gotTC); got.TaskID != "37" || got.AgentKey != "worker" {
			t.Fatalf("executor received wrong routing context: %+v", got)
		}
		return actool.Text("ok"), nil
	}})
	var deny atomic.Bool
	guard := func(ctx context.Context, key string, _ actool.CoreTool, _ *db.Tool, _ json.RawMessage, gotTC *actool.ToolContext) error {
		if agent.RunInfoFrom(ctx) != ri || key != "worker" || gotTC.AgentID != "worker" {
			t.Fatalf("guard received wrong routing context: key=%q info=%+v tc=%+v", key, agent.RunInfoFrom(ctx), gotTC)
		}
		if deny.Load() {
			return fmt.Errorf("route denied")
		}
		return nil
	}
	tool := guardResolvedTools(assemblyCtx, "worker", []actool.CoreTool{base}, nil, []egressToolGuard{guard})[0]
	if res, err := tool.Call(context.Background(), nil, tc); err != nil || res.IsError {
		t.Fatalf("allowed call: result=%+v error=%v", res, err)
	}
	if tc.AgentID != "" {
		t.Fatal("wrapper mutated the caller's shared ToolContext")
	}
	deny.Store(true)
	if res, err := tool.Call(context.Background(), nil, nil); err != nil || !res.IsError || calls != 1 {
		t.Fatalf("denied call reached tool: result=%+v error=%v calls=%d", res, err, calls)
	}
}

func toolGuardTestRuntime(t *testing.T, cfg egressroute.Config) *Server {
	t.Helper()
	m := &Manager{dir: t.TempDir(), pg: &db.DB{}}
	router, err := egressroute.New(cfg, func(context.Context, egressroute.Binding, egressroute.Provider) (string, error) {
		return "", fmt.Errorf("network access is not expected")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.routing = &egressRuntime{m: m, router: router, bindings: map[string]egressroute.Binding{}, tokens: map[string]string{}}
	return &Server{m: m}
}

func TestEgressToolEditorPreviewCannotBypassGuard(t *testing.T) {
	cfg := egressroute.DefaultConfig()
	cfg.Rules = []egressroute.Rule{{ID: "clash", Type: "domain", Value: "example.com", Provider: egressroute.ProviderClash, Enabled: true}}
	s := toolGuardTestRuntime(t, cfg)
	marker := filepath.Join(t.TempDir(), "command-executed")
	body, _ := json.Marshal(map[string]any{"kind": "command", "exec": map[string]any{"command": "touch " + shellQuote(marker)}})
	w := httptest.NewRecorder()
	s.pgTestCustomTool(w, httptest.NewRequest(http.MethodPost, "/api/tools/test", bytes.NewReader(body)))
	var result struct {
		IsError bool   `json:"is_error"`
		Output  string `json:"output"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !result.IsError || !strings.Contains(result.Output, "出口策略拒绝") {
		t.Fatalf("preview did not enforce routing: status=%d body=%s error=%v", w.Code, w.Body.String(), err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("blocked command created its marker: %v", err)
	}
}

func TestEgressToolDefaultTorKeepsCommandExecution(t *testing.T) {
	s := toolGuardTestRuntime(t, egressroute.DefaultConfig())
	execRaw, _ := json.Marshal(map[string]any{"command": "printf default-tor-tool"})
	tool := s.buildCustomTool(&db.Tool{Key: "local_command", Kind: "command", Exec: execRaw})
	result, err := tool.Call(context.Background(), nil, &actool.ToolContext{WorkingDir: s.m.dir})
	if err != nil || result.IsError || !strings.Contains(result.Flatten(), "default-tor-tool") {
		t.Fatalf("default Tor unnecessarily disabled command tools: result=%s error=%v", result.Flatten(), err)
	}
}

func TestEgressHTTPToolUsesTaskContextAndRejectsBorrowedProxy(t *testing.T) {
	s := toolGuardTestRuntime(t, egressroute.DefaultConfig())
	var hits atomic.Int32
	observations := make(chan egressroute.Binding, 1)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		observed, err := s.m.routing.requestSeed(r)
		if err != nil {
			t.Error(err)
		}
		observations <- observed
		w.Write([]byte(`{"ok":true}`))
	}))
	defer gateway.Close()
	s.m.routing.baseURL = gateway.URL
	ri := agent.RunInfo{TaskID: 48}
	ctx := agent.WithRunInfo(context.Background(), ri)
	execRaw, _ := json.Marshal(map[string]any{"url": "http://example.invalid/probe"})
	row := &db.Tool{Key: "http_probe", Kind: "http", Exec: execRaw}
	wrapped := guardResolvedTools(ctx, "worker", []actool.CoreTool{s.buildCustomTool(row)}, map[string]*db.Tool{row.Key: row}, []egressToolGuard{s.guardEgressTool})[0]
	result, err := wrapped.Call(context.Background(), nil, &actool.ToolContext{})
	var observed egressroute.Binding
	select {
	case observed = <-observations:
	default:
		t.Fatal("HTTP tool never contacted its configured gateway")
	}
	if err != nil || result.IsError || observed.TaskID != "48" || observed.AgentKey != "worker" || hits.Load() != 1 {
		t.Fatalf("HTTP did not retain task context: result=%s error=%v binding=%+v hits=%d", result.Flatten(), err, observed, hits.Load())
	}
	borrowed := s.m.routing.proxyURL(egressroute.Binding{TaskID: "49", AgentKey: "worker"}, false)
	borrowedExec, _ := json.Marshal(map[string]any{"url": "http://example.invalid/probe", "proxy": borrowed})
	result, err = s.runHTTPTool(ctx, borrowedExec, nil, &actool.ToolContext{AgentID: "worker"})
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "不能借用") || hits.Load() != 1 {
		t.Fatalf("borrowed context was not denied: result=%s error=%v hits=%d", result.Flatten(), err, hits.Load())
	}
}

func TestEgressHTTPToolInvalidProxyNeverDialsTarget(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte("unexpected direct connection"))
	}))
	defer target.Close()
	s := &Server{}
	for _, spec := range []map[string]any{
		{"url": target.URL, "proxy": "http://"},
		{"url": target.URL, "proxy": "direct://127.0.0.1:1"},
		{"url": target.URL, "use_recording_proxy": true},
	} {
		execRaw, _ := json.Marshal(spec)
		result, err := s.runHTTPTool(context.Background(), execRaw, nil, nil)
		if err != nil || !result.IsError {
			t.Fatalf("invalid proxy should fail closed: result=%s error=%v", result.Flatten(), err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("invalid proxy leaked %d direct requests", hits.Load())
	}
}

func TestEgressHTTPToolRedirectKeepsTaskGateway(t *testing.T) {
	s := toolGuardTestRuntime(t, egressroute.DefaultConfig())
	type observation struct {
		Host string
		Seed egressroute.Binding
	}
	observations := make(chan observation, 2)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seed, err := s.m.routing.requestSeed(r)
		if err != nil {
			t.Error(err)
		}
		observations <- observation{Host: r.URL.Host, Seed: seed}
		if r.URL.Host == "first.invalid" {
			w.Header().Set("Location", "http://second.invalid/finish")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte("redirect reached through task gateway"))
	}))
	defer gateway.Close()
	s.m.routing.baseURL = gateway.URL
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 63})
	execRaw, _ := json.Marshal(map[string]any{"url": "http://first.invalid/start"})
	result, err := s.runHTTPTool(ctx, execRaw, nil, &actool.ToolContext{AgentID: "worker"})
	if err != nil || result.IsError || !strings.Contains(result.Flatten(), "redirect reached through task gateway") {
		t.Fatalf("controlled HTTP redirect failed: result=%s error=%v", result.Flatten(), err)
	}
	for _, expectedHost := range []string{"first.invalid", "second.invalid"} {
		select {
		case got := <-observations:
			if got.Host != expectedHost || got.Seed != (egressroute.Binding{TaskID: "63", AgentKey: "worker"}) {
				t.Fatalf("redirect lost task gateway context: %+v", got)
			}
		default:
			t.Fatalf("gateway did not receive redirect destination %q", expectedHost)
		}
	}
}
