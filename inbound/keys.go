// Package inbound manages the platform's inbound channel: a Tor v3 hidden
// service with mandatory client authorization.
//
// Tor 0.4.9 no longer supports the v2 `HiddenServiceAuthorizeClient` option
// (it logs "Skipping obsolete configuration option"). v3 authorization is
// file-based:
//
//	<HiddenServiceDir>/authorized_clients/<name>.auth
//	  descriptor:x25519:<base32(x25519 public key)>
//
// and the client needs
//
//	<ClientOnionAuthDir>/<name>.auth_private
//	  <56-char onion>:descriptor:x25519:<base32(x25519 private key)>
//
// Neither `tor --keygen` nor the daemon generates these x25519 pairs, so the
// platform owns key generation.
package inbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// b32 is RFC 4648 base32 without padding, the encoding Tor expects for client
// authorization keys. Tor's decoder accepts either case; uppercase matches the
// documentation examples.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ClientKey is one authorized client: the public half goes into the service's
// .auth file, the private half is delivered to the client once.
type ClientKey struct {
	Private []byte // 32 raw bytes
	Public  []byte // 32 raw bytes
}

// GenerateClientKey creates a fresh X25519 pair.
func GenerateClientKey() (*ClientKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("inbound: generate x25519: %w", err)
	}
	return &ClientKey{
		Private: priv.Bytes(),
		Public:  priv.PublicKey().Bytes(),
	}, nil
}

// AuthLine renders the service-side .auth file content for this client.
func (k *ClientKey) AuthLine() string {
	return "descriptor:x25519:" + b32.EncodeToString(k.Public)
}

// ClientLine renders the client-side .auth_private content. onionAddr may be
// the full address ("xxx.onion") or the 56-char form without the suffix.
func (k *ClientKey) ClientLine(onionAddr string) string {
	addr := strings.TrimSuffix(strings.TrimSpace(onionAddr), ".onion")
	return addr + ":descriptor:x25519:" + b32.EncodeToString(k.Private)
}

// PublicFingerprint is a short, non-secret identifier for audit output. It is
// the first 8 bytes of the public key in base32 — enough to tell clients apart
// without being reversible.
func (k *ClientKey) PublicFingerprint() string {
	enc := b32.EncodeToString(k.Public)
	if len(enc) > 13 {
		enc = enc[:13]
	}
	return enc
}

// ParseAuthLine validates a service-side .auth line and returns the public key.
// Used when loading an existing directory so a malformed file is reported
// instead of silently ignored (Tor ignores it, which would look like the
// service has no clients at all).
func ParseAuthLine(line string) ([]byte, error) {
	line = strings.TrimSpace(line)
	parts := strings.Split(line, ":")
	if len(parts) != 3 || parts[0] != "descriptor" || parts[1] != "x25519" {
		return nil, fmt.Errorf("inbound: 非法的 .auth 行（期望 descriptor:x25519:<key>）")
	}
	pub, err := b32.DecodeString(strings.ToUpper(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("inbound: .auth 公钥 base32 解码失败: %w", err)
	}
	if len(pub) != 32 {
		return nil, fmt.Errorf("inbound: .auth 公钥长度 %d，期望 32", len(pub))
	}
	return pub, nil
}

// DecodeBase32Key decodes a base32 key (no padding) of the expected length.
func DecodeBase32Key(s string) ([]byte, error) {
	b, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(s)))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("inbound: 密钥长度 %d，期望 32", len(b))
	}
	return b, nil
}

// EncodeKey base32-encodes a 32-byte key.
func EncodeKey(b []byte) string { return b32.EncodeToString(b) }
