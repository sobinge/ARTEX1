package inbound

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ErrNoClients is returned when a hidden service is about to be enabled without
// any authorized client. Bare onion services are not allowed by design: an
// address leak would open the channel to anyone, and every unexpected connection
// is attack surface.
var ErrNoClients = errors.New("inbound: 未配置任何授权客户端，拒绝启用（不允许裸 Onion）")

// Service is one hidden service directory managed by the platform.
type Service struct {
	Dir     string // HiddenServiceDir
	Target  string // "127.0.0.1:8787" — must be loopback
	Onion   string // filled from <Dir>/hostname once Tor has started
	clients []string
}

// NewService creates (or opens) the hidden service directory and writes the
// torrc fragment the daemon needs. It does NOT start Tor.
func NewService(dir, target string) (*Service, error) {
	target = strings.TrimSpace(target)
	if !isLoopbackTarget(target) {
		return nil, fmt.Errorf("inbound: HiddenServicePort 目标必须只绑回环（收到 %q）", target)
	}
	if err := os.MkdirAll(filepath.Join(dir, "authorized_clients"), 0o700); err != nil {
		return nil, fmt.Errorf("inbound: 创建目录: %w", err)
	}
	s := &Service{Dir: dir, Target: target}
	s.Onion = s.readHostname()
	s.clients = s.readClients()
	return s, nil
}

// isLoopbackTarget enforces the "only bind loopback" rule: mapping a port that
// also listens on 0.0.0.0 would let the target reach the platform by IP, which
// defeats the whole point of the hidden service.
func isLoopbackTarget(target string) bool {
	host := target
	if i := strings.LastIndex(target, ":"); i >= 0 {
		host = target[:i]
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// TorrcFragment is the config the daemon must include for this service.
//
// Tor's syntax is "HiddenServicePort <VIRTPORT> [<TARGET>]", so the loopback
// target alone is NOT a valid line — writing "HiddenServicePort 127.0.0.1:8899"
// makes Tor read 127.0.0.1:8899 as the virtual port and refuse to start
// ("Missing or invalid port ..."). The onion-side port is chosen equal to the
// target port so the address means the same port on both ends.
func (s *Service) TorrcFragment() string {
	return fmt.Sprintf("HiddenServiceDir %s\nHiddenServiceVersion 3\nHiddenServicePort %d %s\n",
		s.Dir, virtualPort(s.Target), s.Target)
}

// virtualPort extracts the port from host:port, defaulting to 80 when absent.
func virtualPort(target string) int {
	if i := strings.LastIndex(target, ":"); i >= 0 {
		if p, err := strconv.Atoi(target[i+1:]); err == nil && p > 0 && p < 65536 {
			return p
		}
	}
	return 80
}

// Clients lists authorized client names (the .auth file basenames).
func (s *Service) Clients() []string { return append([]string(nil), s.clients...) }

// AddClient generates a keypair, installs the public half and returns the client
// secret exactly once. The caller must deliver it and must not store it.
func (s *Service) AddClient(name string) (secret string, fingerprint string, err error) {
	name = sanitizeClientName(name)
	if name == "" {
		return "", "", errors.New("inbound: 客户端名不能为空")
	}
	if s.Onion == "" {
		return "", "", errors.New("inbound: 服务尚未生成 onion 地址，先启动一次 Tor")
	}
	key, err := GenerateClientKey()
	if err != nil {
		return "", "", err
	}
	path := filepath.Join(s.Dir, "authorized_clients", name+".auth")
	if err := os.WriteFile(path, []byte(key.AuthLine()+"\n"), 0o600); err != nil {
		return "", "", fmt.Errorf("inbound: 写入 .auth: %w", err)
	}
	s.clients = s.readClients()
	return key.ClientLine(s.Onion) + "\n", key.PublicFingerprint(), nil
}

// RevokeClient removes the client's .auth file. Tor only picks the change up on
// SIGHUP/restart, so callers must reload the daemon (see Reloader).
func (s *Service) RevokeClient(name string) error {
	name = sanitizeClientName(name)
	path := filepath.Join(s.Dir, "authorized_clients", name+".auth")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inbound: 删除 .auth: %w", err)
	}
	s.clients = s.readClients()
	return nil
}

// EnsureEnabled refuses to enable a service with no authorized clients. This is
// the code-level enforcement of the "no bare onion" rule; the torrc fragment
// must only be written/applied after this passes.
func (s *Service) EnsureEnabled() error {
	clients := s.readClients()
	if len(clients) == 0 {
		return ErrNoClients
	}
	s.clients = clients
	return nil
}

func (s *Service) readHostname() string {
	b, err := os.ReadFile(filepath.Join(s.Dir, "hostname"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (s *Service) readClients() []string {
	entries, err := os.ReadDir(filepath.Join(s.Dir, "authorized_clients"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".auth") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".auth"))
	}
	sort.Strings(out)
	return out
}

// sanitizeClientName keeps the file name predictable and traversal-free.
func sanitizeClientName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Reloader triggers a Tor config reload. Implemented by tor.Client in the server
// wiring; kept as an interface so this package stays dependency-free.
type Reloader interface {
	SignalReload(ctx context.Context) error
}
