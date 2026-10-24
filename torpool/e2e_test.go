//go:build e2e

// End-to-end tests against real Tor daemons. They are excluded from the normal
// test run because they need the `tor` binary and a working route to the Tor
// network (or an upstream proxy, see ARTEX_TOR_UPSTREAM).
//
//	ARTEX_TOR_UPSTREAM=127.0.0.1:7897 go test ./torpool/ -tags e2e -run E2E -v -timeout 20m
package torpool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// torIPFixed asks a FIXED destination for the observed IP. A CDN hostname
// (check.torproject.org) resolves to many addresses, and Tor opens one circuit
// per destination address — which makes exit IPs look unstable between probes
// even when nothing rotated. 1.1.1.1 is a single anycast address, so repeated
// probes reuse the same circuit and any change means a real circuit change.
func torIPFixed(ctx context.Context, socksAddr string) (string, error) {
	u, err := url.Parse("socks5://" + socksAddr)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimSpace(line[3:]), nil
		}
	}
	return "", fmt.Errorf("no ip= in trace response: %q", string(b))
}

// circuitIDs lists the IDs of currently known circuits on one instance.
func circuitIDs(ctx context.Context, inst *Instance) (map[string]bool, error) {
	reply, err := inst.Client().GetInfo(ctx, "circuit-status")
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, line := range strings.Split(reply, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if _, err := strconv.Atoi(f[0]); err == nil {
			ids[f[0]] = true
		}
	}
	return ids, nil
}

// torExitIP asks the Tor project's check endpoint through one SOCKS port.
func torExitIP(ctx context.Context, socksAddr string) (ip string, isTor bool, err error) {
	u, err := url.Parse("socks5://" + socksAddr)
	if err != nil {
		return "", false, err
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return "", false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", false, err
	}
	var out struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", false, fmt.Errorf("unexpected body %q: %w", string(body), err)
	}
	return out.IP, out.IsTor, nil
}

func e2ePool(t *testing.T, size int) *Pool {
	t.Helper()
	if _, err := exec.LookPath("tor"); err != nil {
		t.Skip("tor binary not installed")
	}
	cfg := Config{
		Dir:            t.TempDir(),
		Size:           size,
		SocksBase:      19350,
		ControlBase:    19450,
		StartupTimeout: 5 * time.Minute,
		UpstreamProxy:  strings.TrimSpace(os.Getenv("ARTEX_TOR_UPSTREAM")),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Stop)
	return p
}

// TestE2EPoolTwoDaemonsRouteThroughTor is the baseline: two independent daemons
// come up, each reaches the Tor network, and the control-cookie auth works.
func TestE2EPoolTwoDaemonsRouteThroughTor(t *testing.T) {
	p := e2ePool(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	for _, inst := range p.Instances() {
		ip, isTor, err := torExitIP(ctx, inst.SocksAddr)
		if err != nil {
			t.Fatalf("instance %d exit probe: %v", inst.ID, err)
		}
		if !isTor {
			t.Fatalf("instance %d is not going through Tor (ip=%s)", inst.ID, ip)
		}
		t.Logf("instance %d: socks=%s exit=%s tor=%v", inst.ID, inst.SocksAddr, ip, isTor)
	}
}

// TestE2ENewNymIsScopedToInstance is the property the pool exists for: rotating
// one agent's slot must not rebuild another agent's circuits.
//
// The check is circuit-based, not IP-based: a NEWNYM makes the next stream build
// a fresh circuit, so "no new circuit ID appeared on slot 2" is the precise
// statement of "slot 2 was not rotated".
func TestE2ENewNymIsScopedToInstance(t *testing.T) {
	p := e2ePool(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	inst1, inst2 := p.Instance(1), p.Instance(2)

	ip1Before, err := torIPFixed(ctx, inst1.SocksAddr)
	if err != nil {
		t.Fatalf("instance 1 probe: %v", err)
	}
	ip2Before, err := torIPFixed(ctx, inst2.SocksAddr)
	if err != nil {
		t.Fatalf("instance 2 probe: %v", err)
	}
	idsBefore, err := circuitIDs(ctx, inst2)
	if err != nil {
		t.Fatalf("circuit-status instance 2: %v", err)
	}
	t.Logf("before: inst1=%s inst2=%s inst2circuits=%d", ip1Before, ip2Before, len(idsBefore))

	if _, err := p.NewNym(ctx, "agent-under-test", 1); err != nil {
		t.Fatalf("NewNym instance 1: %v", err)
	}

	// Slot 1 must move (retry: NEWNYM is rate-limited and circuit build takes time).
	var ip1After string
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(12 * time.Second)
		ip1After, err = torIPFixed(ctx, inst1.SocksAddr)
		if err != nil {
			t.Logf("inst1 retry: %v", err)
			continue
		}
		if ip1After != ip1Before {
			break
		}
	}

	// Slot 2: probe again and compare circuits — this is the scoping proof.
	ip2After, err := torIPFixed(ctx, inst2.SocksAddr)
	if err != nil {
		t.Fatalf("instance 2 re-probe: %v", err)
	}
	idsAfter, err := circuitIDs(ctx, inst2)
	if err != nil {
		t.Fatalf("circuit-status instance 2 (after): %v", err)
	}
	newIDs := []string{}
	for id := range idsAfter {
		if !idsBefore[id] {
			newIDs = append(newIDs, id)
		}
	}
	t.Logf("after:  inst1=%s inst2=%s inst2circuits=%d new=%v", ip1After, ip2After, len(idsAfter), newIDs)

	if len(newIDs) > 0 {
		t.Fatalf("rotating instance 1 built new circuits on instance 2: %v", newIDs)
	}
	if ip2After != ip2Before {
		t.Fatalf("instance 2 exit changed without rotation: %s -> %s", ip2Before, ip2After)
	}
	if ip1After == ip1Before {
		t.Fatalf("instance 1 exit did not change after NEWNYM (still %s)", ip1Before)
	}
	if ip1After == "" {
		t.Fatal("instance 1 probe returned empty IP")
	}
}
