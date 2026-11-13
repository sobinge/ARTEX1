package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/egressroute"
	"github.com/Autumn-27/artex/traffic"
)

const settingEgressRouting = "egress_routing"
const clashProxyURL = "http://127.0.0.1:7890"

type clashRuntimeStatus struct {
	Enabled   bool   `json:"enabled"`
	Ready     bool   `json:"ready"`
	NodeCount int    `json:"node_count"`
	Selected  string `json:"selected,omitempty"`
	Error     string `json:"error,omitempty"`
}

type egressRuntime struct {
	m            *Manager
	router       *egressroute.Router
	baseURL      string
	http         *http.Server
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.Mutex
	configMu     sync.Mutex
	bindings     map[string]egressroute.Binding
	tokens       map[string]string
	clash        clashRuntimeStatus
	clashChecked time.Time
	audit        chan egressroute.AuditEvent
	ctx          context.Context
	platform     map[string]string
}

func (m *Manager) startEgressRouting() error {
	cfg := egressroute.DefaultConfig()
	if raw, ok, err := m.pg.GetSetting(settingEgressRouting); err != nil {
		return err
	} else if ok {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return fmt.Errorf("invalid saved routing configuration: %w", err)
		}
	}
	var err error
	if cfg, err = validateRoutingConfig(cfg); err != nil {
		return err
	}
	if _, err := m.pg.Exec(`CREATE TABLE IF NOT EXISTS egress_route_events (
		id BIGSERIAL PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), detail JSONB NOT NULL
	); CREATE INDEX IF NOT EXISTS egress_route_events_created ON egress_route_events(created_at DESC)`); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt := &egressRuntime{m: m, bindings: map[string]egressroute.Binding{}, tokens: map[string]string{}, audit: make(chan egressroute.AuditEvent, 256), ctx: ctx, cancel: cancel, platform: platformHosts()}
	rt.router, err = egressroute.New(cfg, rt.resolveProxy, rt.recordEvent)
	if err != nil {
		cancel()
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		return err
	}
	rt.baseURL = "http://" + listener.Addr().String()
	rt.http = &http.Server{ReadHeaderTimeout: 15 * time.Second, Handler: rt.gatewayHandler()}
	m.routing = rt
	if m.traffic != nil {
		m.traffic.SetUpstreamResolver(func(r *http.Request) (*url.URL, error) {
			seed, err := rt.requestSeed(r)
			if err != nil {
				return nil, err
			}
			return url.Parse(rt.proxyURL(seed, false))
		})
	}
	rt.wg.Add(2)
	go func() {
		defer rt.wg.Done()
		if err := rt.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[egress] routing gateway stopped: %v", err)
		}
	}()
	go func() { defer rt.wg.Done(); rt.auditWorker() }()
	log.Printf("[egress] Tor/Clash routing gateway on %s; automatic fallback=%t", listener.Addr(), cfg.Fallback.Enabled)
	return nil
}

func (rt *egressRuntime) gatewayHandler() http.Handler {
	handler := rt.router.Handler(rt.requestBinding)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := rt.requestSeed(r); err != nil {
			http.Error(w, "出口认证失效，请刷新连接", http.StatusProxyAuthRequired)
			return
		}
		if destination, ok := rt.platformAddress(r); ok {
			rt.servePlatform(w, r, destination)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func validateRoutingConfig(cfg egressroute.Config) (egressroute.Config, error) {
	if cfg.ClashProxy == "" {
		cfg.ClashProxy = clashProxyURL
	}
	if cfg.ClashProxy != clashProxyURL {
		return cfg, fmt.Errorf("Clash 出口必须使用受控本地入口 %s", clashProxyURL)
	}
	return cfg.Validate()
}

func (rt *egressRuntime) Close() {
	rt.cancel()
	_ = rt.http.Close()
	rt.router.CloseIdleConnections()
	rt.wg.Wait()
}

// Tokens carry only a server-side lookup key; no subscription, upstream proxy
// password or routing policy is encoded in URLs passed to tools or the recorder.
func (rt *egressRuntime) proxyURL(seed egressroute.Binding, capture bool) string {
	keyBytes, _ := json.Marshal(seed)
	key := string(keyBytes)
	rt.mu.Lock()
	token := rt.tokens[key]
	if token == "" {
		var random [24]byte
		if _, err := rand.Read(random[:]); err != nil {
			rt.mu.Unlock()
			return blackholeProxy
		}
		token = hex.EncodeToString(random[:])
		rt.tokens[key], rt.bindings[token] = token, seed
	}
	rt.mu.Unlock()
	base := rt.baseURL
	if capture && rt.m.traffic != nil && rt.m.TrafficEnabled() {
		base = rt.m.traffic.ProxyAddr()
	}
	u, err := url.Parse(base)
	if err != nil {
		return blackholeProxy
	}
	u.User = url.UserPassword(token, "route")
	return u.String()
}

func (rt *egressRuntime) requestSeed(r *http.Request) (egressroute.Binding, error) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return egressroute.Binding{}, nil
	}
	if !strings.HasPrefix(auth, "Basic ") {
		return egressroute.Binding{}, errors.New("invalid proxy authentication")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return egressroute.Binding{}, errors.New("invalid proxy authentication")
	}
	token, password, ok := strings.Cut(string(decoded), ":")
	if !ok || password != "route" {
		return egressroute.Binding{}, errors.New("invalid proxy authentication")
	}
	rt.mu.Lock()
	seed, ok := rt.bindings[token]
	rt.mu.Unlock()
	if !ok {
		return egressroute.Binding{}, errors.New("expired proxy authentication")
	}
	return seed, nil
}

func (rt *egressRuntime) requestBinding(r *http.Request) (egressroute.Binding, error) {
	seed, err := rt.requestSeed(r)
	if err != nil {
		return seed, err
	}
	return rt.binding(seed)
}

// Bindings are looked up on every new request/tunnel, so a persisted task or
// Agent switch applies without a stale per-agent proxy cache.
func (rt *egressRuntime) binding(seed egressroute.Binding) (egressroute.Binding, error) {
	b := seed
	b.AgentKey = canonicalEgressAgent(b.AgentKey)
	if b.Mode != "" && b.Mode != "inherit" {
		return rt.checkBinding(b)
	}
	if b.TaskID != "" {
		id, err := strconv.ParseInt(b.TaskID, 10, 64)
		if err != nil || id <= 0 {
			return b, errors.New("invalid task routing context")
		}
		mode, proxy, err := rt.m.pg.TaskEgress(id)
		if err != nil {
			return b, fmt.Errorf("读取任务出口失败；不会回退直连: %w", err)
		}
		if mode != "" && mode != "inherit" {
			b.Mode, b.ProxyURL = mode, proxy
			return rt.checkBinding(b)
		}
	}
	if b.AgentKey != "" {
		a, err := rt.m.pg.GetAgentByKey(b.AgentKey)
		if err != nil {
			return b, fmt.Errorf("读取 Agent 出口失败；不会回退直连: %w", err)
		}
		if a != nil && a.EgressMode != "" && a.EgressMode != "inherit" {
			b.Mode, b.ProxyURL = a.EgressMode, a.EgressProxy
			return rt.checkBinding(b)
		}
	}
	// The controlled router defaults to Tor after target rules. The legacy
	// global proxy remains available to platform clients, but must not silently
	// override target rules or turn the Tor default into an unrelated proxy.
	return rt.checkBinding(b)
}

func (rt *egressRuntime) checkBinding(b egressroute.Binding) (egressroute.Binding, error) {
	if b.Mode == "direct" {
		return b, errors.New("目标流量不允许直连；平台/内网白名单保持独立策略；不会回退直连")
	}
	return b, nil
}

func (rt *egressRuntime) resolveProxy(ctx context.Context, b egressroute.Binding, provider egressroute.Provider) (string, error) {
	switch provider {
	case egressroute.ProviderTor:
		a := &db.Agent{Key: b.AgentKey, EgressMode: "tor"}
		if b.AgentKey != "" {
			if saved, err := rt.m.pg.GetAgentByKey(b.AgentKey); err != nil {
				return "", err
			} else if saved != nil {
				copy := *saved
				a = &copy
				a.EgressMode = "tor"
			}
		}
		plan, err := (&Server{m: rt.m}).resolveEgress(a, "")
		if err != nil {
			return "", err
		}
		if (a.TorCircuitKey == "" || a.TorCircuitKey == "task") && b.TaskID != "" {
			plan.ProxyURL = torSocksURL(plan.ProxyURL, "task-"+b.TaskID)
		}
		return plan.ProxyURL, nil
	case egressroute.ProviderClash:
		status := rt.clashStatus(ctx)
		if !status.Ready || status.NodeCount < 1 {
			return "", fmt.Errorf("Clash 没有可用代理节点；不会回退直连: %s", status.Error)
		}
		return clashProxyURL, nil
	case egressroute.ProviderProxy:
		if strings.TrimSpace(b.ProxyURL) == "" {
			return "", errors.New("未配置显式代理；不会回退直连")
		}
		if _, err := traffic.ValidateProxyURL(b.ProxyURL); err != nil {
			return "", err
		}
		return b.ProxyURL, nil
	default:
		return "", errors.New("未知出口类型；不会回退直连")
	}
}

func (rt *egressRuntime) clashStatus(ctx context.Context) clashRuntimeStatus {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if time.Since(rt.clashChecked) < 2*time.Second {
		return rt.clash
	}
	status := clashRuntimeStatus{Enabled: os.Getenv("ARTEX_CLASH_ENABLED") == "1"}
	if !status.Enabled {
		status.Error = "Clash 尚未启用"
	} else {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		body, err := exec.CommandContext(probeCtx, "/usr/local/bin/artex-clash-config.py", "status").Output()
		if err != nil {
			status.Error = "Clash 服务或严格节点配置不可用"
		} else if err := json.Unmarshal(body, &status); err != nil {
			status.Error = "Clash 状态响应无效"
			status.Ready = false
		}
		status.Enabled = true
	}
	rt.clash, rt.clashChecked = status, time.Now()
	return status
}

func (rt *egressRuntime) recordEvent(event egressroute.AuditEvent) {
	select {
	case <-rt.ctx.Done():
		return
	default:
	}
	select {
	case rt.audit <- event:
	case <-rt.ctx.Done():
	}
}

// Policy changes have no observed IP: a switch takes effect on the next target
// request, whose separate event records the selected route and probe provenance.
func (rt *egressRuntime) recordPolicyChange(reason, taskID, agentKey, mode string) {
	detail, _ := json.Marshal(map[string]any{
		"timestamp": time.Now().UTC(), "event_type": "policy-change", "method": "POLICY",
		"task_id": taskID, "agent_key": agentKey, "provider": mode, "host": "",
		"reason": reason, "success": true,
	})
	if _, err := rt.m.pg.Exec(`INSERT INTO egress_route_events(detail) VALUES($1::jsonb)`, string(detail)); err != nil {
		log.Printf("[egress] policy audit persistence failed: %v", err)
	}
}

func (rt *egressRuntime) auditWorker() {
	type cachedProbe struct {
		probe egressProbe
		at    time.Time
	}
	cache := map[string]cachedProbe{}
	for {
		select {
		case <-rt.ctx.Done():
			return
		case event := <-rt.audit:
			body, _ := json.Marshal(event)
			var detail map[string]any
			_ = json.Unmarshal(body, &detail)
			detail["timestamp"] = detail["at"]
			if event.Success {
				key := string(event.Provider) + "|" + event.TaskID + "|" + event.AgentKey
				entry := cache[key]
				if time.Since(entry.at) > time.Minute {
					seed := egressroute.Binding{TaskID: event.TaskID, AgentKey: event.AgentKey}
					b, err := rt.binding(seed)
					if err == nil {
						ctx, cancel := context.WithTimeout(rt.ctx, 15*time.Second)
						proxy, resolveErr := rt.resolveProxy(ctx, b, event.Provider)
						if resolveErr == nil {
							entry = cachedProbe{probe: probeEgress(ctx, EgressPlan{Mode: string(event.Provider), ProxyURL: proxy}), at: time.Now()}
							cache[key] = entry
						}
						cancel()
					}
				}
				if entry.probe.IP != "" {
					detail["exit_ip"], detail["is_tor"] = entry.probe.IP, entry.probe.IsTor
					detail["exit_ip_source"] = "same-provider-probe"
				}
			}
			body, _ = json.Marshal(detail)
			if _, err := rt.m.pg.Exec(`INSERT INTO egress_route_events(detail) VALUES($1::jsonb)`, string(body)); err != nil && rt.ctx.Err() == nil {
				log.Printf("[egress] audit persistence failed: %v", err)
			}
		}
	}
}

// Platform exceptions are matched against literal private addresses and the
// deployment's pinned /etc/hosts entries only. Public target DNS is never used
// to manufacture a direct exception.
func platformHosts() map[string]string {
	allowed := map[string]bool{}
	for _, raw := range strings.FieldsFunc(os.Getenv("ARTEX_DIRECT_IPS"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if ip := net.ParseIP(raw); ip != nil {
			allowed[ip.String()] = true
		}
	}
	hosts := map[string]string{"localhost": "127.0.0.1"}
	if file, err := os.Open("/etc/hosts"); err == nil {
		defer file.Close()
		scan := bufio.NewScanner(file)
		for scan.Scan() {
			line, _, _ := strings.Cut(scan.Text(), "#")
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			ip := net.ParseIP(fields[0])
			if ip == nil {
				continue
			}
			if ip.IsPrivate() || ip.IsLoopback() || allowed[ip.String()] {
				for _, host := range fields[1:] {
					hosts[strings.ToLower(host)] = ip.String()
				}
			}
		}
	}
	for ip := range allowed {
		hosts[ip] = ip
	}
	return hosts
}

func (rt *egressRuntime) platformAddress(r *http.Request) (string, bool) {
	host := r.URL.Hostname()
	port := r.URL.Port()
	if r.Method == http.MethodConnect {
		var err error
		host, port, err = net.SplitHostPort(r.Host)
		if err != nil {
			return "", false
		}
	}
	if port == "" {
		port = "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
	}
	if pinned, ok := rt.platform[strings.ToLower(strings.TrimSuffix(host, "."))]; ok {
		return net.JoinHostPort(pinned, port), true
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
		return net.JoinHostPort(ip.String(), port), true
	}
	return "", false
}

func (rt *egressRuntime) servePlatform(w http.ResponseWriter, r *http.Request, destination string) {
	if r.Method == http.MethodConnect {
		conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(r.Context(), "tcp", destination)
		if err != nil {
			http.Error(w, "平台连接失败", 502)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			conn.Close()
			http.Error(w, "tunnel unsupported", 500)
			return
		}
		client, buffer, err := hj.Hijack()
		if err != nil {
			conn.Close()
			return
		}
		defer client.Close()
		defer conn.Close()
		if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if buffer.Flush() != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(conn, buffer)
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			close(done)
		}()
		_, _ = io.Copy(client, conn)
		_ = client.Close()
		_ = conn.Close()
		<-done
		return
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", destination)
	}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.Header = r.Header.Clone()
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	response, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, "平台连接失败", 502)
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}
