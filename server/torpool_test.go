package server

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/torpool"
)

func newPoolForTest(t *testing.T, size int) *torpool.Pool {
	t.Helper()
	pool, err := torpool.New(torpool.Config{
		Dir:         t.TempDir(),
		Size:        size,
		SocksBase:   19050,
		ControlBase: 19150,
	})
	if err != nil {
		t.Fatalf("torpool.New: %v", err)
	}
	// Adopt protocol stubs so routing tests use a genuinely started pool and
	// still exercise the same readiness checks as a real Tor process.
	for _, inst := range pool.Instances() {
		if err := os.MkdirAll(filepath.Dir(inst.CookiePath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inst.CookiePath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
			t.Fatal(err)
		}
		socks, err := net.Listen("tcp", inst.SocksAddr)
		if err != nil {
			t.Skipf("cannot bind test SOCKS: %v", err)
		}
		t.Cleanup(func() { socks.Close() })
		ctrl, err := net.Listen("tcp", inst.ControlAddr)
		if err != nil {
			t.Skipf("cannot bind test control: %v", err)
		}
		t.Cleanup(func() { ctrl.Close() })
		go func() {
			for {
				conn, err := ctrl.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					br := bufio.NewReader(conn)
					if _, err := br.ReadString('\n'); err != nil {
						return
					}
					conn.Write([]byte("250 OK\r\n"))
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "GETINFO config-file"):
						conn.Write([]byte("250-config-file=" + inst.TorrcPath + "\r\n250 OK\r\n"))
					case strings.HasPrefix(line, "GETINFO status/bootstrap-phase"):
						conn.Write([]byte("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n"))
					case strings.HasPrefix(line, "SIGNAL SHUTDOWN"):
						conn.Write([]byte("250 OK\r\n"))
						ctrl.Close()
						socks.Close()
					}
				}()
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := pool.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Stop)
	return pool
}

// Pooled mode must route each agent to its own slot so NEWNYM stays per-agent.
func TestResolveEgressPoolRoutesPinnedSlot(t *testing.T) {
	pool := newPoolForTest(t, 3)
	m := &Manager{egressStrict: true, torPool: pool, torPoolEnabled: true, torPoolSize: 3}
	s := &Server{m: m}

	a := &db.Agent{Key: "scanner", EgressMode: "tor", EgressTorInstance: 2}
	plan, err := s.resolveEgress(a, "task-1")
	if err != nil {
		t.Fatalf("resolveEgress: %v", err)
	}
	if plan.TorInstance != 2 {
		t.Fatalf("TorInstance = %d, want 2", plan.TorInstance)
	}
	if !strings.Contains(plan.ProxyURL, "127.0.0.1:19051") {
		t.Fatalf("proxy = %q, want slot-2 socks port", plan.ProxyURL)
	}
	if !strings.HasPrefix(plan.ProxyURL, "socks5h://") {
		t.Fatalf("proxy must stay socks5h (remote DNS): %q", plan.ProxyURL)
	}
	if !plan.IsTor {
		t.Fatal("plan must be marked tor")
	}
}

// Auto assignment must be stable: moving exits between runs would be visible to
// the target as a change of origin.
func TestResolveEgressPoolAutoAssignmentIsStable(t *testing.T) {
	pool := newPoolForTest(t, 3)
	m := &Manager{egressStrict: true, torPool: pool, torPoolEnabled: true, torPoolSize: 3}
	s := &Server{m: m}
	a := &db.Agent{Key: "recon", EgressMode: "tor"}

	first, err := s.resolveEgress(a, "t")
	if err != nil {
		t.Fatalf("resolveEgress: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := s.resolveEgress(a, "t")
		if err != nil {
			t.Fatalf("resolveEgress: %v", err)
		}
		if again.TorInstance != first.TorInstance || again.ProxyURL != first.ProxyURL {
			t.Fatalf("assignment drifted: %d/%s -> %d/%s",
				first.TorInstance, first.ProxyURL, again.TorInstance, again.ProxyURL)
		}
	}
}

// Without a pool the legacy single daemon must still be used.
func TestResolveEgressPoolDisabledFallsBackToSingleDaemon(t *testing.T) {
	m := &Manager{egressStrict: true, torSocksAddr: "socks5h://10.0.0.9:9050", torPoolEnabled: false}
	s := &Server{m: m}
	a := &db.Agent{Key: "scanner", EgressMode: "tor"}
	plan, err := s.resolveEgress(a, "")
	if err != nil {
		t.Fatalf("resolveEgress: %v", err)
	}
	if plan.TorInstance != 0 {
		t.Fatalf("TorInstance = %d, want 0 (shared daemon)", plan.TorInstance)
	}
	if !strings.Contains(plan.ProxyURL, "10.0.0.9:9050") {
		t.Fatalf("proxy = %q", plan.ProxyURL)
	}
}

func TestValidateTorInstance(t *testing.T) {
	m := &Manager{torPoolEnabled: true, torPoolSize: 3}
	s := &Server{m: m}
	if v, err := s.validateTorInstance(0); err != nil || v != 0 {
		t.Fatalf("auto slot rejected: %d %v", v, err)
	}
	if _, err := s.validateTorInstance(-1); err == nil {
		t.Fatal("negative slot accepted")
	}
	if v, err := s.validateTorInstance(3); err != nil || v != 3 {
		t.Fatalf("valid slot rejected: %d %v", v, err)
	}
	if _, err := s.validateTorInstance(4); err == nil {
		t.Fatal("slot beyond pool size accepted")
	}
	off := &Manager{torPoolEnabled: false, torPoolSize: 3}
	so := &Server{m: off}
	if _, err := so.validateTorInstance(1); err == nil {
		t.Fatal("pin accepted while pool disabled")
	}
}

func TestResolveEgressInheritUsesReadyTorPool(t *testing.T) {
	pool := newPoolForTest(t, 3)
	s := &Server{m: &Manager{egressStrict: true, torPool: pool, torPoolEnabled: true}}
	a := &db.Agent{Key: "worker", EgressMode: "inherit", EgressTorInstance: 2, TorCircuitKey: "agent"}
	plan, err := s.resolveEgress(a, "task-1")
	if err != nil || plan.TorInstance != 2 || plan.ProxyURL != "socks5h://agent-worker:x@127.0.0.1:19051" || !plan.IsTor {
		t.Fatalf("inherit failed to use isolated pooled Tor: %+v, err=%v", plan, err)
	}
	s.m.globalProxy = "http://explicit:8080"
	plan, err = s.resolveEgress(a, "task-1")
	if err != nil || plan.ProxyURL != "http://explicit:8080" {
		t.Fatalf("explicit global proxy lost precedence: %+v, err=%v", plan, err)
	}
	a.EgressMode, a.EgressProxy = "proxy", "http://agent:8080"
	plan, err = s.resolveEgress(a, "task-1")
	if err != nil || plan.ProxyURL != a.EgressProxy {
		t.Fatalf("explicit agent proxy lost precedence: %+v, err=%v", plan, err)
	}
}

func TestResolveEgressUnavailablePoolFailsClosed(t *testing.T) {
	unstarted, err := torpool.New(torpool.Config{Dir: t.TempDir(), Size: 1, SocksBase: 19050, ControlBase: 19150})
	if err != nil {
		t.Fatal(err)
	}
	for _, pool := range []*torpool.Pool{nil, unstarted} {
		for _, strict := range []bool{false, true} {
			s := &Server{m: &Manager{torPoolEnabled: true, torPool: pool, egressStrict: strict, torSocksAddr: "127.0.0.1:9050"}}
			for _, mode := range []string{"inherit", "tor"} {
				if _, err := s.resolveEgress(&db.Agent{Key: "worker", EgressMode: mode}, "task"); err == nil || !strings.Contains(err.Error(), "不会回退直连") {
					t.Fatalf("unavailable pool must refuse (strict=%v mode=%s): %v", strict, mode, err)
				}
			}
			if proxy, _ := s.egressProxyFor("worker", "task"); proxy != blackholeProxy {
				t.Fatalf("unavailable pool escaped blackhole: %q", proxy)
			}
		}
	}
}

func TestStartTorPoolFailureStopsOldPoolAndClearsReference(t *testing.T) {
	old := newPoolForTest(t, 1)
	m := &Manager{torPool: old, torPoolEnabled: true, torPoolSize: 1, torPoolSocksBase: 19050, torPoolControlBase: 19150, torPoolDir: t.TempDir(), torBinary: "/nonexistent/tor"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.StartTorPool(ctx); err == nil {
		t.Fatal("missing executable unexpectedly started")
	}
	if old.Started() || m.TorPool() != nil {
		t.Fatal("restart failure left an old or half-started pool published")
	}
}

func TestStopTorPoolCancelsConcurrentBootstrap(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "tor-stub")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 60\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{torPoolEnabled: true, torPoolSize: 1, torPoolSocksBase: 19050, torPoolControlBase: 19150, torPoolDir: t.TempDir(), torBinary: bin}
	result := make(chan error, 1)
	go func() { result <- m.StartTorPool(context.Background()) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		m.mu.RLock()
		starting := m.torPoolCancel != nil
		m.mu.RUnlock()
		if starting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bootstrap did not begin")
		}
		time.Sleep(time.Millisecond)
	}
	m.StopTorPool()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled bootstrap unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not cancel bootstrap promptly")
	}
	if m.TorPool() != nil {
		t.Fatal("pool was published after Stop")
	}
}
