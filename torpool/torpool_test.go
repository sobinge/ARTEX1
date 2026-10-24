package torpool

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Binary:              "tor",
		Dir:                 t.TempDir(),
		Size:                3,
		SocksBase:           19050,
		ControlBase:         19150,
		MaxCircuitDirtiness: 600,
		StartupTimeout:      2 * time.Second,
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"zero size", func(c *Config) { c.Size = 0 }, "size"},
		{"too large", func(c *Config) { c.Size = 64 }, "too large"},
		{"empty dir", func(c *Config) { c.Dir = "  " }, "dir is required"},
		{"bad socks", func(c *Config) { c.SocksBase = 0 }, "socks base"},
		{"overlap", func(c *Config) { c.SocksBase = 19100; c.ControlBase = 19100 }, "overlaps"},
		{"range overflow", func(c *Config) { c.SocksBase = 65535; c.ControlBase = 100; c.Size = 4 }, "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New() error = %v, want contains %q", err, tc.want)
			}
		})
	}
}

func TestNewAssignsDistinctPorts(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seen := map[int]bool{}
	for _, inst := range p.Instances() {
		if seen[inst.SocksPort] || seen[inst.ControlPort] {
			t.Fatalf("port collision at instance %d", inst.ID)
		}
		seen[inst.SocksPort], seen[inst.ControlPort] = true, true
		if inst.SocksAddr != "127.0.0.1:"+itoa(inst.SocksPort) {
			t.Fatalf("socks addr mismatch: %s", inst.SocksAddr)
		}
		if !strings.HasSuffix(inst.CookiePath, "control_auth_cookie") {
			t.Fatalf("cookie path = %q", inst.CookiePath)
		}
	}
	if p.Size() != 3 {
		t.Fatalf("Size() = %d", p.Size())
	}
}

func TestTorrcContainsIsolationDirectives(t *testing.T) {
	cfg := testConfig(t)
	cfg.ExitCountry = "SG"
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inst := p.Instance(2)
	body := p.cfg.torrc(*inst)
	for _, want := range []string{
		"SocksPort 127.0.0.1:19051 IsolateSOCKSAuth",
		"ControlPort 127.0.0.1:19151",
		"CookieAuthentication 1",
		"CookieAuthFile " + inst.CookiePath,
		"DataDirectory " + inst.DataDir,
		"ClientOnly 1",
		"MaxCircuitDirtiness 600",
		"ExitNodes {sg}",
		"StrictNodes 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("torrc missing %q\n%s", want, body)
		}
	}
}

func TestTorrcOmitsExitPinWhenUnset(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body := p.cfg.torrc(*p.Instance(1))
	if strings.Contains(body, "ExitNodes") {
		t.Fatalf("unexpected ExitNodes:\n%s", body)
	}
}

func TestForIsStableAndOverrideWins(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a1 := p.For("scanner", 0)
	a2 := p.For("scanner", 0)
	if a1 != a2 {
		t.Fatalf("assignment not stable: %d vs %d", a1.ID, a2.ID)
	}
	if got := p.For("scanner", 3); got.ID != 3 {
		t.Fatalf("override ignored, got %d", got.ID)
	}
	if got := p.For("scanner", 99); got != a1 {
		t.Fatalf("out-of-range override should fall back to hash, got %d", got.ID)
	}
	// Different agents should not all collapse onto one slot.
	ids := map[int]bool{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		ids[p.For(k, 0).ID] = true
	}
	if len(ids) < 2 {
		t.Fatalf("hash assignment collapsed to %d slot(s)", len(ids))
	}
}

func TestStartFailsWithMissingBinary(t *testing.T) {
	cfg := testConfig(t)
	cfg.Binary = filepath.Join(t.TempDir(), "no-such-tor")
	cfg.Size = 1
	cfg.StartupTimeout = 800 * time.Millisecond
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = p.Start(context.Background())
	if err == nil {
		p.Stop()
		t.Fatal("Start() succeeded with missing binary")
	}
	if p.Started() {
		t.Fatal("pool marked started after failed Start")
	}
}

func TestWaitReadyTimesOutWithoutListener(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inst := p.Instance(1)
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := waitReady(ctx, inst); err == nil {
		t.Fatal("waitReady succeeded with no daemon")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("waitReady did not honour the context deadline")
	}
}

func TestWaitReadySucceedsWhenPortsAndCookieExist(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inst := p.Instance(1)
	if err := os.MkdirAll(filepath.Dir(inst.CookiePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inst.CookiePath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	socks, err := net.Listen("tcp", inst.SocksAddr)
	if err != nil {
		t.Skipf("cannot bind %s: %v", inst.SocksAddr, err)
	}
	defer socks.Close()
	ctrl, err := net.Listen("tcp", inst.ControlAddr)
	if err != nil {
		t.Skipf("cannot bind %s: %v", inst.ControlAddr, err)
	}
	defer ctrl.Close()
	// Minimal control-protocol stub: answer AUTHENTICATE, then report a finished
	// bootstrap so waitReady's GETINFO gate is satisfied.
	go func() {
		for {
			conn, err := ctrl.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(conn)
			if _, err := br.ReadString('\n'); err == nil {
				conn.Write([]byte("250 OK\r\n"))
				if _, err := br.ReadString('\n'); err == nil {
					conn.Write([]byte("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n"))
				}
			}
			conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := waitReady(ctx, inst); err != nil {
		t.Fatalf("waitReady: %v", err)
	}
}

func TestNewNymWithoutInstances(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p.NewNym(context.Background(), "agent", 0); err == nil {
		t.Fatal("NewNym should fail when daemons are not running")
	}
}

func TestStatusShape(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st := p.Status()
	if st.Started || st.Size != 3 || len(st.Instances) != 3 {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Instances[0].Running {
		t.Fatal("instance reported running before Start")
	}
	if !strings.Contains(st.Ports, "socks=19050..19052") {
		t.Fatalf("ports summary = %q", st.Ports)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

func TestTorrcUpstreamProxyWithAndWithoutCredentials(t *testing.T) {
	cfg := testConfig(t)
	cfg.UpstreamProxy = "127.0.0.1:7897"
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body := p.cfg.torrc(*p.Instance(1))
	if !strings.Contains(body, "HTTPSProxy 127.0.0.1:7897") {
		t.Fatalf("missing HTTPSProxy:\n%s", body)
	}
	if strings.Contains(body, "HTTPSProxyAuthenticator") {
		t.Fatalf("unexpected authenticator:\n%s", body)
	}

	cfg.UpstreamProxy = "user:p%40ss@127.0.0.1:7897"
	cfg.Dir = t.TempDir()
	p2, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body = p2.cfg.torrc(*p2.Instance(1))
	if !strings.Contains(body, "HTTPSProxy 127.0.0.1:7897") ||
		!strings.Contains(body, "HTTPSProxyAuthenticator user:p%40ss") {
		t.Fatalf("credential handling wrong:\n%s", body)
	}
}

// adoptStub serves the control protocol enough for recogniseOwnDaemon: cookie
// present, config-file pointing at the instance's torrc.
func adoptStub(t *testing.T, addr, cfgFile string) (stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot bind %s: %v", addr, err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(conn)
			if _, err := br.ReadString('\n'); err != nil {
				conn.Close()
				continue
			}
			conn.Write([]byte("250 OK\r\n"))
			line, err := br.ReadString('\n')
			if err != nil {
				conn.Close()
				continue
			}
			if strings.HasPrefix(line, "GETINFO config-file") {
				conn.Write([]byte("250-config-file=" + cfgFile + "\r\n250 OK\r\n"))
			} else {
				conn.Write([]byte("250 OK\r\n"))
			}
			conn.Close()
		}
	}()
	return func() { ln.Close() }
}

// A restart must adopt its own still-running daemon instead of failing to bind.
func TestStartAdoptsOwnRunningDaemon(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inst := p.Instance(1)
	if err := os.MkdirAll(filepath.Dir(inst.CookiePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inst.CookiePath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopCtrl := adoptStub(t, inst.ControlAddr, inst.TorrcPath)
	defer stopCtrl()
	socks, err := net.Listen("tcp", inst.SocksAddr)
	if err != nil {
		t.Skipf("bind socks: %v", err)
	}
	defer socks.Close()

	cfg, ok := p.recogniseOwnDaemon(context.Background(), inst)
	if !ok {
		t.Fatal("recogniseOwnDaemon did not adopt its own daemon")
	}
	if cfg != inst.TorrcPath {
		t.Fatalf("config-file = %q", cfg)
	}
}

// A foreign Tor on the same port must NOT be adopted.
func TestRecogniseRejectsForeignDaemon(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inst := p.Instance(1)
	if err := os.MkdirAll(filepath.Dir(inst.CookiePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inst.CookiePath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopCtrl := adoptStub(t, inst.ControlAddr, "/etc/tor/torrc")
	defer stopCtrl()

	if _, ok := p.recogniseOwnDaemon(context.Background(), inst); ok {
		t.Fatal("adopted a daemon that is not ours")
	}
}
