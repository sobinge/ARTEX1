package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/inbound"
	"github.com/Autumn-27/artex/tor"
)

// onionBaseDir is where hidden-service directories live. It sits under the data
// dir so a backup/restore of data/ carries the service identity with it.
func (s *Server) onionBaseDir() string {
	return filepath.Join(s.m.dir, "inbound", "onion")
}

// onionService loads or creates a named service.
func (s *Server) onionService(name, target string) (*inbound.Service, error) {
	name = sanitizeOnionName(name)
	if name == "" {
		return nil, errText("服务名不能为空")
	}
	return inbound.NewService(filepath.Join(s.onionBaseDir(), name), target)
}

type errText string

func (e errText) Error() string { return string(e) }

func sanitizeOnionName(name string) string {
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

// listOnionServices reports every managed hidden service.
func (s *Server) listOnionServices(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(s.onionBaseDir())
	out := []map[string]any{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		svc, err := inbound.NewService(filepath.Join(s.onionBaseDir(), e.Name()), "127.0.0.1:0")
		if err != nil {
			continue
		}
		out = append(out, map[string]any{
			"name":      e.Name(),
			"onion":     svc.Onion,
			"clients":   svc.Clients(),
			"clients_n": len(svc.Clients()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	writeJSON(w, 200, map[string]any{"services": out})
}

// createOnionService creates a hidden-service directory plus its torrc fragment.
// The service is NOT live until the operator applies the fragment and starts Tor.
func (s *Server) createOnionService(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Target string `json:"target"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		req.Target = "127.0.0.1:8787"
	}
	svc, err := s.onionService(req.Name, req.Target)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"dir":     svc.Dir,
		"torrc":   svc.TorrcFragment(),
		"onion":   svc.Onion,
		"clients": svc.Clients(),
		"note":    "把 torrc 片段加入 Tor 配置并重启，才会生成 onion 地址；未添加授权客户端前平台拒绝启用。",
	})
}

// addOnionClient authorizes a client and returns its .auth_private content ONCE.
func (s *Server) addOnionClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Client string `json:"client"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	svc, err := s.onionService(name, "127.0.0.1:8787")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	secret, fp, err := svc.AddClient(req.Client)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// Apply immediately if a control port is configured; otherwise tell the
	// operator to reload Tor themselves.
	applied := false
	if addr := s.m.TorControlAddr(); addr != "" {
		c := &tor.Client{Addr: addr, CookiePath: s.m.TorCookiePath()}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		applied = c.SignalReload(ctx) == nil
	}
	writeJSON(w, 200, map[string]any{
		"ok":           true,
		"client":       req.Client,
		"fingerprint":  fp,
		"auth_private": secret,
		"applied":      applied,
		"note":         "客户端密钥只返回这一次，平台不保存；未 applied 时请自行重启/重载 Tor。",
	})
}

// revokeOnionClient removes a client's authorization and reloads Tor.
func (s *Server) revokeOnionClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	client := r.PathValue("client")
	svc, err := s.onionService(name, "127.0.0.1:8787")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := svc.RevokeClient(client); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	applied := false
	if addr := s.m.TorControlAddr(); addr != "" {
		c := &tor.Client{Addr: addr, CookiePath: s.m.TorCookiePath()}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		applied = c.SignalReload(ctx) == nil
	}
	writeJSON(w, 200, map[string]any{"ok": true, "applied": applied, "clients": svc.Clients()})
}

// enableOnionService enforces the "no bare onion" rule at the API boundary.
func (s *Server) enableOnionService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	svc, err := s.onionService(name, "127.0.0.1:8787")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := svc.EnsureEnabled(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "torrc": svc.TorrcFragment(), "clients": svc.Clients()})
}
