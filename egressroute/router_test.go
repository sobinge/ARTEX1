package egressroute

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func rulesConfig() Config {
	c := DefaultConfig()
	c.Rules = []Rule{
		{ID: "exact", Type: "domain", Value: "special.example.com", Provider: ProviderClash, Enabled: true},
		{ID: "suffix", Type: "suffix", Value: "example.com", Provider: ProviderTor, AllowFallback: true, Enabled: true},
		{ID: "ip", Type: "ip", Value: "203.0.113.9", Provider: ProviderClash, Enabled: true},
		{ID: "cidr", Type: "cidr", Value: "198.51.100.0/24", Provider: ProviderClash, Enabled: true},
	}
	return c
}

func TestRulePriorityExplicitModesAndNoDNSExpansion(t *testing.T) {
	r, err := New(rulesConfig(), func(context.Context, Binding, Provider) (string, error) { return "", errors.New("not dialed") }, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host, mode string
		provider   Provider
		rule       string
	}{
		{"special.example.com", "", ProviderClash, "exact"},
		{"child.example.com", "", ProviderTor, "suffix"},
		{"badexample.com", "", ProviderTor, ""},
		{"EXAMPLE.com.", "", ProviderTor, "suffix"},
		{"203.0.113.9", "", ProviderClash, "ip"},
		{"198.51.100.42:443", "", ProviderClash, "cidr"},
		{"unresolved.invalid", "", ProviderTor, ""},
		{"special.example.com", "tor", ProviderTor, ""},
		{"child.example.com", "clash", ProviderClash, ""},
		{"child.example.com", "proxy", ProviderProxy, ""},
	} {
		d, err := r.Select(Binding{Mode: test.mode}, test.host)
		if err != nil || d.Provider != test.provider || d.RuleID != test.rule {
			t.Errorf("%+v => %+v, %v", test, d, err)
		}
		if test.mode != "" && d.AllowFallback {
			t.Error("explicit route allowed fallback")
		}
	}
	if _, err := r.Select(Binding{Mode: "direct"}, "example.com"); err == nil {
		t.Error("direct accepted")
	}
}

func TestValidateRejectsAmbiguousAndDirectRoutes(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Rules[0].Provider = "direct" },
		func(c *Config) { c.Rules[0].AllowFallback = true },
		func(c *Config) { c.Rules[0].Value = "example.com.evil/" },
		func(c *Config) { c.Rules[1].ID = c.Rules[0].ID },
		func(c *Config) { c.ClashProxy = "direct://" },
		func(c *Config) { c.Fallback.CooldownSeconds = -1 },
	} {
		c := rulesConfig()
		mutate(&c)
		if _, err := c.Validate(); err == nil {
			t.Error("invalid configuration accepted")
		}
	}
}

func fallbackConfig() Config {
	c := DefaultConfig()
	c.Fallback = FallbackConfig{Enabled: true, FailureThreshold: 2, CooldownSeconds: 10}
	c.Rules = []Rule{{ID: "may-fallback", Type: "suffix", Value: "example.com", Provider: ProviderTor, AllowFallback: true, Enabled: true}}
	return c
}

func request(t *testing.T, r *Router, binding Binding, method, target string, body io.Reader) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	return r.RoundTripper(binding).RoundTrip(req)
}

func TestFallbackThresholdScopeCooldownAndRecovery(t *testing.T) {
	var clashCalls atomic.Int32
	clash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { clashCalls.Add(1); fmt.Fprint(w, "clash") }))
	defer clash.Close()
	var torReady atomic.Bool
	tor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "tor") }))
	defer tor.Close()
	var mu sync.Mutex
	var events []AuditEvent
	r, err := New(fallbackConfig(), func(_ context.Context, b Binding, p Provider) (string, error) {
		if p == ProviderClash {
			return clash.URL, nil
		}
		if torReady.Load() {
			return tor.URL, nil
		}
		return "", errors.New("Tor is unavailable")
	}, func(event AuditEvent) { mu.Lock(); events = append(events, event); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	defer r.CloseIdleConnections()
	now := time.Now()
	r.now = func() time.Time { return now }
	b := Binding{TaskID: "1", AgentKey: "worker"}
	if resp, err := request(t, r, b, "GET", "http://a.example.com/", nil); err == nil {
		resp.Body.Close()
		t.Fatal("first failure should not cross threshold")
	}
	resp, err := request(t, r, b, "GET", "http://a.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "clash" || clashCalls.Load() != 1 {
		t.Fatalf("fallback response=%q calls=%d", body, clashCalls.Load())
	}
	d, _ := r.Select(b, "a.example.com")
	if d.Provider != ProviderClash || !d.InFallback {
		t.Fatalf("fallback not sticky: %+v", d)
	}
	for _, other := range []struct {
		b    Binding
		host string
	}{{Binding{TaskID: "2", AgentKey: "worker"}, "a.example.com"}, {Binding{TaskID: "1", AgentKey: "planner"}, "a.example.com"}, {b, "b.example.com"}} {
		d, _ := r.Select(other.b, other.host)
		if d.Provider != ProviderTor {
			t.Errorf("fallback escaped its target context: %+v", d)
		}
	}
	now = now.Add(11 * time.Second)
	torReady.Store(true)
	resp, err = request(t, r, b, "GET", "http://a.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "tor" {
		t.Fatalf("did not recover to Tor: %q", body)
	}
	if len(r.Snapshot().States) != 0 {
		t.Error("successful Tor trial retained failure state")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 4 || events[2].Provider != ProviderClash || events[2].Reason != "tor-failure-threshold" {
		t.Fatalf("audit=%+v", events)
	}
}

func TestFallbackRequiresBothGlobalAndTargetAuthorization(t *testing.T) {
	for _, kind := range []string{"global-disabled", "rule-disabled", "explicit-tor", "no-rule"} {
		t.Run(kind, func(t *testing.T) {
			cfg := fallbackConfig()
			cfg.Fallback.FailureThreshold = 1
			binding := Binding{}
			switch kind {
			case "global-disabled":
				cfg.Fallback.Enabled = false
			case "rule-disabled":
				cfg.Rules[0].AllowFallback = false
			case "explicit-tor":
				binding.Mode = "tor"
			case "no-rule":
				cfg.Rules = nil
			}
			var clash atomic.Int32
			r, _ := New(cfg, func(_ context.Context, _ Binding, p Provider) (string, error) {
				if p == ProviderClash {
					clash.Add(1)
				}
				return "", errors.New("unavailable")
			}, nil)
			_, err := request(t, r, binding, "GET", "http://a.example.com/", nil)
			if err == nil || clash.Load() != 0 {
				t.Fatalf("unauthorized fallback err=%v clash=%d", err, clash.Load())
			}
		})
	}
}

func TestPOSTIsNotReplayedEvenWithGetBodyAndIdempotencyKey(t *testing.T) {
	var torCalls, clashCalls atomic.Int32
	tor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		torCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	}))
	defer tor.Close()
	clash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { clashCalls.Add(1); fmt.Fprint(w, "unexpected") }))
	defer clash.Close()
	cfg := fallbackConfig()
	cfg.Fallback.FailureThreshold = 1
	r, _ := New(cfg, func(_ context.Context, _ Binding, p Provider) (string, error) {
		if p == ProviderTor {
			return tor.URL, nil
		}
		return clash.URL, nil
	}, nil)
	defer r.CloseIdleConnections()
	req, _ := http.NewRequest("POST", "http://a.example.com/", strings.NewReader("write once"))
	req.Header.Set("Idempotency-Key", "test")
	if response, err := r.RoundTripper(Binding{}).RoundTrip(req); err == nil {
		response.Body.Close()
		t.Fatal("POST unexpectedly succeeded")
	}
	if torCalls.Load() != 1 || clashCalls.Load() != 0 {
		t.Fatalf("POST replayed: Tor=%d Clash=%d", torCalls.Load(), clashCalls.Load())
	}
}

func TestBothProxyFailuresNeverDialTargetOrEnvironmentProxy(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	t.Setenv("HTTP_PROXY", target.URL)
	t.Setenv("HTTPS_PROXY", target.URL)
	t.Setenv("ALL_PROXY", target.URL)
	cfg := fallbackConfig()
	cfg.Fallback.FailureThreshold = 1
	// Match the literal sentinel destination, so both approved providers fail.
	u, _ := url.Parse(target.URL)
	cfg.Rules = []Rule{{ID: "local-sentinel", Type: "ip", Value: u.Hostname(), Provider: ProviderTor, AllowFallback: true, Enabled: true}}
	var attempts atomic.Int32
	r, _ := New(cfg, func(context.Context, Binding, Provider) (string, error) { attempts.Add(1); return "", nil }, nil)
	_, err := request(t, r, Binding{}, "GET", target.URL, nil)
	if err == nil || attempts.Load() != 2 || targetCalls.Load() != 0 {
		t.Fatalf("direct/environment leak: err=%v attempts=%d target=%d", err, attempts.Load(), targetCalls.Load())
	}
}

func TestHTTPProxyReceivesOnlyItsOwnCredentialsAndAuditIsRedacted(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Proxy-Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	u.User = url.UserPassword("node-user", "node-secret")
	var events []AuditEvent
	r, _ := New(DefaultConfig(), func(context.Context, Binding, Provider) (string, error) { return u.String(), nil }, func(e AuditEvent) { events = append(events, e) })
	defer r.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "http://never-resolve.invalid/", nil)
	req.Header.Set("Proxy-Authorization", "Basic contextual-secret")
	resp, err := r.RoundTripper(Binding{}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "Basic bm9kZS11c2VyOm5vZGUtc2VjcmV0" {
		t.Fatalf("upstream authorization=%q", got)
	}
	if len(events) != 1 || strings.Contains(events[0].ProxyHint, "node-secret") || strings.Contains(events[0].ProxyHint, "node-user") {
		t.Fatalf("credential leaked to audit: %+v", events)
	}
}

func TestSOCKSRemoteDNSAndCONNECT(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan string, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var head [2]byte
		io.ReadFull(c, head[:])
		methods := make([]byte, int(head[1]))
		io.ReadFull(c, methods)
		c.Write([]byte{5, 0})
		var requestHead [5]byte
		io.ReadFull(c, requestHead[:])
		if requestHead[3] != 3 {
			observed <- "not a hostname"
			return
		}
		host := make([]byte, int(requestHead[4]))
		io.ReadFull(c, host)
		var port [2]byte
		io.ReadFull(c, port[:])
		observed <- fmt.Sprintf("%s:%d", host, binary.BigEndian.Uint16(port[:]))
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		c.Write([]byte("banner"))
	}()
	r, _ := New(DefaultConfig(), func(context.Context, Binding, Provider) (string, error) {
		return "socks5h://" + listener.Addr().String(), nil
	}, nil)
	c, decision, err := r.DialContext(context.Background(), Binding{}, "tcp", "do-not-resolve.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 6)
	if _, err = io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "banner" || decision.Provider != ProviderTor || <-observed != "do-not-resolve.invalid:443" {
		t.Fatal("SOCKS target was not resolved by the proxy")
	}
}

func TestCONNECTFallbackBufferedBytesAndGatewayAuthentication(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "target.invalid:443" {
			t.Errorf("upstream request %s %s", r.Method, r.Host)
			http.Error(w, "bad", 400)
			return
		}
		c, b, _ := w.(http.Hijacker).Hijack()
		defer c.Close()
		fmt.Fprint(b, "HTTP/1.1 200 Connection Established\r\n\r\nbanner")
		b.Flush()
		data := make([]byte, 4)
		if _, err := io.ReadFull(b, data); err == nil {
			fmt.Fprint(c, strings.ToUpper(string(data)))
		}
	}))
	defer upstream.Close()
	cfg := fallbackConfig()
	cfg.Fallback.FailureThreshold = 1
	cfg.Rules[0].Value = "target.invalid"
	r, _ := New(cfg, func(_ context.Context, _ Binding, p Provider) (string, error) {
		if p == ProviderTor {
			return "", errors.New("Tor failed before payload")
		}
		return upstream.URL, nil
	}, nil)
	gateway := httptest.NewServer(r.Handler(func(req *http.Request) (Binding, error) {
		if req.Header.Get("Proxy-Authorization") != "Basic context-token" {
			return Binding{}, errors.New("unauthenticated")
		}
		return Binding{TaskID: "42", AgentKey: "worker"}, nil
	}))
	defer gateway.Close()
	u, _ := url.Parse(gateway.URL)
	c, err := net.DialTimeout("tcp", u.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\nProxy-Authorization: Basic context-token\r\n\r\nping")
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT response=%v err=%v", response, err)
	}
	data := make([]byte, 10)
	if _, err = io.ReadFull(reader, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "bannerPING" {
		t.Fatalf("buffered/pipelined bytes lost: %q", data)
	}
	resp, err := http.Get(gateway.URL + "/unauthenticated")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 407 {
		t.Fatalf("unauthed proxy response %d", resp.StatusCode)
	}
}

func TestConcurrentSelectionAndUpdate(t *testing.T) {
	r, _ := New(rulesConfig(), func(context.Context, Binding, Provider) (string, error) { return "", errors.New("offline") }, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				r.Select(Binding{TaskID: "x"}, "example.com")
				r.Config()
				r.Snapshot()
			}
		}()
	}
	for n := 0; n < 100; n++ {
		if err := r.Update(rulesConfig()); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
