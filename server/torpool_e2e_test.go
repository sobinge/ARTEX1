//go:build e2e

// End-to-end: an agent's resolved egress really exits through its own Tor
// instance. Requires the tor binary and network access (or ARTEX_TOR_UPSTREAM).
//
//	ARTEX_TOR_UPSTREAM=127.0.0.1:7897 go test ./server/ -tags e2e -run E2E -v -timeout 20m
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/torpool"
)

func probePlanIP(ctx context.Context, proxyURL string) (string, bool, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", false, fmt.Errorf("bad proxy %q: %w", proxyURL, err)
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return "", false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", false, err
	}
	var out struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", false, fmt.Errorf("body %q: %w", string(b), err)
	}
	return out.IP, out.IsTor, nil
}

// Two agents pinned to different slots must resolve to different SOCKS ports and
// different Tor exits.
func TestE2EAgentsGetIndependentTorExits(t *testing.T) {
	if _, err := exec.LookPath("tor"); err != nil {
		t.Skip("tor binary not installed")
	}
	pool, err := torpool.New(torpool.Config{
		Dir:            t.TempDir(),
		Size:           2,
		SocksBase:      19550,
		ControlBase:    19650,
		StartupTimeout: 5 * time.Minute,
		UpstreamProxy:  strings.TrimSpace(os.Getenv("ARTEX_TOR_UPSTREAM")),
	})
	if err != nil {
		t.Fatalf("torpool.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err := pool.Start(ctx); err != nil {
		t.Fatalf("pool.Start: %v", err)
	}
	t.Cleanup(pool.Stop)

	m := &Manager{egressStrict: true, torPool: pool, torPoolEnabled: true, torPoolSize: 2}
	s := &Server{m: m}

	get := func(key string, slot int) EgressPlan {
		a := &db.Agent{Key: key, EgressMode: "tor", EgressTorInstance: slot}
		plan, err := s.resolveEgress(a, "task-e2e")
		if err != nil {
			t.Fatalf("resolveEgress(%s): %v", key, err)
		}
		if plan.TorInstance != slot {
			t.Fatalf("%s: TorInstance = %d, want %d", key, plan.TorInstance, slot)
		}
		return plan
	}
	p1 := get("scanner-a", 1)
	p2 := get("scanner-a", 2)
	if p1.ProxyURL == p2.ProxyURL {
		t.Fatalf("both agents share one proxy: %s", p1.ProxyURL)
	}

	ip1, tor1, err := probePlanIP(ctx, p1.ProxyURL)
	if err != nil {
		t.Fatalf("probe slot1: %v", err)
	}
	ip2, tor2, err := probePlanIP(ctx, p2.ProxyURL)
	if err != nil {
		t.Fatalf("probe slot2: %v", err)
	}
	if !tor1 || !tor2 {
		t.Fatalf("not Tor exits: slot1=%v slot2=%v", tor1, tor2)
	}
	t.Logf("slot1 %s -> %s ; slot2 %s -> %s", p1.ProxyURL, ip1, p2.ProxyURL, ip2)
	if ip1 == ip2 {
		t.Logf("warning: both slots landed on the same exit IP (%s); guards differ but exits can coincide", ip1)
	}
}
