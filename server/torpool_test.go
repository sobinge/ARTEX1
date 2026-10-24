package server

import (
	"strings"
	"testing"

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
