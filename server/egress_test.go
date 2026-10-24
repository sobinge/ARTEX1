package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func newEgressTestServer(globalProxy, torAddr string, strict bool) *Server {
	m := &Manager{globalProxy: globalProxy, torSocksAddr: torAddr, egressStrict: strict}
	return &Server{m: m}
}

func TestResolveEgressStrictWithoutProxyFailsClosed(t *testing.T) {
	s := newEgressTestServer("", "", true)
	if _, err := s.resolveEgress(nil, "42"); err == nil {
		t.Fatal("strict + no egress must fail, not dial direct")
	} else if !strings.Contains(err.Error(), "不会回退直连") {
		t.Errorf("error must state no direct fallback: %v", err)
	}
}

func TestResolveEgressNonStrictIsDirect(t *testing.T) {
	s := newEgressTestServer("", "", false)
	plan, err := s.resolveEgress(nil, "")
	if err != nil {
		t.Fatalf("non-strict with no proxy: %v", err)
	}
	if plan.Mode != "direct" {
		t.Errorf("mode = %q, want direct", plan.Mode)
	}
}

func TestResolveEgressInheritsSocksGlobalAsTor(t *testing.T) {
	s := newEgressTestServer("socks5h://172.18.0.1:9050", "", true)
	plan, err := s.resolveEgress(nil, "7")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !plan.IsTor || plan.Mode != "tor" {
		t.Errorf("socks5 global must resolve to tor, got %+v", plan)
	}
	if !strings.HasPrefix(plan.ProxyURL, "socks5h://") {
		t.Errorf("tor egress must use socks5h, got %q", plan.ProxyURL)
	}
}

func TestResolveEgressExplicitTorWithCircuitUser(t *testing.T) {
	s := newEgressTestServer("", "socks5h://172.18.0.1:9050", true)
	a := &db.Agent{Key: "worker", EgressMode: "tor", TorCircuitKey: "task"}
	plan, err := s.resolveEgress(a, "42")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if plan.CircuitUser != "task-42" {
		t.Errorf("circuit user = %q, want task-42", plan.CircuitUser)
	}
	if plan.ProxyURL != "socks5h://task-42:x@172.18.0.1:9050" {
		t.Errorf("proxy url = %q", plan.ProxyURL)
	}

	a.TorCircuitKey = "agent"
	plan, _ = s.resolveEgress(a, "42")
	if plan.CircuitUser != "agent-worker" {
		t.Errorf("circuit user = %q, want agent-worker", plan.CircuitUser)
	}
}

func TestResolveEgressExplicitDirectRefusedWhenStrict(t *testing.T) {
	s := newEgressTestServer("socks5h://172.18.0.1:9050", "", true)
	a := &db.Agent{Key: "worker", EgressMode: "direct"}
	if _, err := s.resolveEgress(a, "1"); err == nil {
		t.Fatal("explicit direct must be refused under strict mode")
	}
}

func TestResolveEgressTorWithoutAddressFails(t *testing.T) {
	s := newEgressTestServer("", "", true)
	a := &db.Agent{Key: "worker", EgressMode: "tor"}
	if _, err := s.resolveEgress(a, "1"); err == nil {
		t.Fatal("tor mode without address must fail")
	}
}

func TestTorSocksURLKeepsCredentialsAndForcesSocks5h(t *testing.T) {
	cases := map[string]string{
		"socks5://h:1":     "socks5h://h:1",
		"socks5h://h:1":    "socks5h://h:1",
		"socks5://u:p@h:1": "socks5h://u:p@h:1",
		"172.18.0.1:9050":  "socks5h://172.18.0.1:9050",
	}
	for in, want := range cases {
		if got := torSocksURL(in, ""); got != want {
			t.Errorf("torSocksURL(%q) = %q, want %q", in, got, want)
		}
	}
	if got := torSocksURL("socks5h://h:1", "task-9"); got != "socks5h://task-9:x@h:1" {
		t.Errorf("circuit user not applied: %q", got)
	}
}

func TestEgressProxyForFailsClosedToBlackhole(t *testing.T) {
	s := newEgressTestServer("", "", true)
	addr, ca := s.egressProxyFor("worker", "1")
	if addr != blackholeProxy {
		t.Fatalf("strict without egress must blackhole, got %q", addr)
	}
	if ca != "" {
		t.Errorf("blackhole must not carry a CA: %q", ca)
	}
}

func TestEgressProxyForDirectWhenNotStrict(t *testing.T) {
	s := newEgressTestServer("", "", false)
	if addr, _ := s.egressProxyFor("worker", "1"); addr != "" {
		t.Errorf("non-strict with no proxy should be direct, got %q", addr)
	}
}

func TestCanonicalEgressAgent(t *testing.T) {
	cases := map[string]string{
		"work#1":  "worker",
		"work#12": "worker",
		"plan#2":  "planner",
		"worker":  "worker",
		"planner": "planner",
		"":        "",
	}
	for in, want := range cases {
		if got := canonicalEgressAgent(in); got != want {
			t.Errorf("canonicalEgressAgent(%q) = %q, want %q", in, got, want)
		}
	}
}
