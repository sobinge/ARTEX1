package inbound

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientKeyRoundTrip(t *testing.T) {
	k, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseAuthLine(k.AuthLine())
	if err != nil {
		t.Fatalf("ParseAuthLine: %v", err)
	}
	if string(pub) != string(k.Public) {
		t.Fatal("public key round-trip mismatch")
	}
	if len(k.PublicFingerprint()) == 0 || len(k.PublicFingerprint()) > 13 {
		t.Fatalf("bad fingerprint %q", k.PublicFingerprint())
	}
}

func TestParseAuthLineRejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"",
		"descriptor:x25519",
		"descriptor:ed25519:AAAA",
		"descriptor:x25519:not-base32!!",
		"descriptor:x25519:AAAA", // too short
	} {
		if _, err := ParseAuthLine(bad); err == nil {
			t.Errorf("ParseAuthLine(%q) should fail", bad)
		}
	}
}

func TestClientLineFormat(t *testing.T) {
	k, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	onion := strings.Repeat("a", 56) + ".onion"
	line := k.ClientLine(onion)
	if strings.Contains(line, ".onion") {
		t.Errorf("client line must drop the .onion suffix: %q", line)
	}
	// .auth_private is <addr>:descriptor:x25519:<key> — four colon-separated parts.
	parts := strings.Split(strings.TrimSpace(line), ":")
	if len(parts) != 4 || parts[1] != "descriptor" || parts[2] != "x25519" {
		t.Fatalf("bad client line %q", line)
	}
	if parts[0] != strings.Repeat("a", 56) {
		t.Errorf("address mangled: %q", parts[0])
	}
	// The embedded key must decode back to the private key.
	priv, err := DecodeBase32Key(parts[3])
	if err != nil {
		t.Fatalf("decode private: %v", err)
	}
	if string(priv) != string(k.Private) {
		t.Fatal("private key mismatch")
	}
}

func TestNewServiceRejectsNonLoopback(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewService(dir, "0.0.0.0:8787"); err == nil {
		t.Fatal("non-loopback target must be rejected")
	}
	if _, err := NewService(dir, "172.18.0.1:8787"); err == nil {
		t.Fatal("bridge address must be rejected")
	}
}

func TestEnsureEnabledRequiresClient(t *testing.T) {
	dir := t.TempDir()
	s, err := NewService(dir, "127.0.0.1:8787")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureEnabled(); err != ErrNoClients {
		t.Fatalf("empty service: got %v, want ErrNoClients", err)
	}
}

func TestAddAndRevokeClient(t *testing.T) {
	dir := t.TempDir()
	s, err := NewService(dir, "127.0.0.1:8787")
	if err != nil {
		t.Fatal(err)
	}
	// Tor writes hostname on first start; simulate that.
	onion := strings.Repeat("b", 56) + ".onion"
	if err := os.WriteFile(filepath.Join(dir, "hostname"), []byte(onion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = NewService(dir, "127.0.0.1:8787")
	if err != nil {
		t.Fatal(err)
	}

	secret, fp, err := s.AddClient("Agent 01")
	if err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(secret), strings.Repeat("b", 56)+":descriptor:x25519:") {
		t.Fatalf("bad secret %q", secret)
	}
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
	if err := s.EnsureEnabled(); err != nil {
		t.Fatalf("EnsureEnabled after AddClient: %v", err)
	}
	if got := s.Clients(); len(got) != 1 || got[0] != "agent01" {
		t.Fatalf("clients = %v, want [agent01]", got)
	}

	// The .auth file must be 0600 and contain exactly one valid line.
	body, err := os.ReadFile(filepath.Join(dir, "authorized_clients", "agent01.auth"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAuthLine(string(body)); err != nil {
		t.Fatalf("written .auth invalid: %v", err)
	}

	if err := s.RevokeClient("agent01"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureEnabled(); err != ErrNoClients {
		t.Fatalf("after revoke: got %v, want ErrNoClients", err)
	}
}

// Tor rejects "HiddenServicePort <target>" — the first token must be the virtual
// port. This regression produced exactly that bug: the onion daemon refused to
// start with "Missing or invalid port \"127.0.0.1:8899\"".
func TestTorrcFragmentUsesVirtualPortSyntax(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewService(dir, "127.0.0.1:8899")
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	got := svc.TorrcFragment()
	want := "HiddenServicePort 8899 127.0.0.1:8899"
	if !strings.Contains(got, want) {
		t.Fatalf("fragment missing %q:\n%s", want, got)
	}
	if !strings.Contains(got, "HiddenServiceVersion 3") {
		t.Fatalf("fragment must pin v3:\n%s", got)
	}
	if strings.Contains(got, "HiddenServicePort 127.0.0.1:8899\n") {
		t.Fatalf("fragment still uses target-only syntax:\n%s", got)
	}
}

func TestVirtualPortDefaults(t *testing.T) {
	if p := virtualPort("127.0.0.1:8899"); p != 8899 {
		t.Fatalf("virtualPort = %d", p)
	}
	if p := virtualPort("localhost"); p != 80 {
		t.Fatalf("virtualPort(no port) = %d", p)
	}
}
