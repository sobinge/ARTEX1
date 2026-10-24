package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/torpool"
)

// ---------------------------------------------------------------------------
// Manager side: build / start / stop the pooled Tor daemons.
// ---------------------------------------------------------------------------

// TorPoolEnabled reports whether per-agent Tor daemons are in use.
func (m *Manager) TorPoolEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.torPoolEnabled
}

// TorPool returns the running pool, or nil when disabled/not started.
func (m *Manager) TorPool() *torpool.Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.torPool
}

// TorPoolSize returns the configured slot count (independent of whether the
// daemons are currently running — the UI needs the saved value to render and
// re-save it).
func (m *Manager) TorPoolSize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.torPoolSize
}

// TorPoolPorts returns the configured base ports (slot 1) for the UI.
func (m *Manager) TorPoolPorts() (socks, control int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.torPoolSocksBase, m.torPoolControlBase
}

// TorPoolUpstream returns the daemons' upstream proxy setting.
func (m *Manager) TorPoolUpstream() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.torPoolUpstream
}

// StartTorPool launches the daemons described by the persisted settings.
// It is a no-op when the pool is disabled: callers then keep using the single
// shared daemon (backwards compatible installs).
func (m *Manager) StartTorPool(ctx context.Context) error {
	m.mu.Lock()
	cfg := torpool.Config{
		Binary:        m.torBinary,
		Dir:           m.torPoolDir,
		Size:          m.torPoolSize,
		SocksBase:     m.torPoolSocksBase,
		ControlBase:   m.torPoolControlBase,
		UpstreamProxy: m.torPoolUpstream,
	}
	enabled := m.torPoolEnabled
	old := m.torPool
	m.mu.Unlock()

	if !enabled {
		if old != nil {
			old.Stop()
		}
		m.mu.Lock()
		m.torPool = nil
		m.mu.Unlock()
		return nil
	}

	pool, err := torpool.New(cfg)
	if err != nil {
		return err
	}
	if err := pool.Start(ctx); err != nil {
		return err
	}
	if old != nil {
		old.Stop()
	}
	m.mu.Lock()
	m.torPool = pool
	m.mu.Unlock()
	return nil
}

// StopTorPool terminates all pooled daemons.
func (m *Manager) StopTorPool() {
	m.mu.Lock()
	pool := m.torPool
	m.torPool = nil
	m.mu.Unlock()
	if pool != nil {
		pool.Stop()
	}
}

// TorPoolStatus returns the current pool state for the UI. A disabled pool
// reports size 0 rather than an error so the settings page can render it.
func (m *Manager) TorPoolStatus() torpool.Status {
	m.mu.RLock()
	pool := m.torPool
	dir, binary := m.torPoolDir, m.torBinary
	size := m.torPoolSize
	enabled := m.torPoolEnabled
	socksBase, controlBase := m.torPoolSocksBase, m.torPoolControlBase
	m.mu.RUnlock()

	if pool != nil {
		st := pool.Status()
		st.Enabled = enabled
		return st
	}
	return torpool.Status{
		Enabled: enabled,
		Size:    0,
		Dir:     dir,
		Binary:  binary,
		Ports: fmt.Sprintf("socks=%d..%d control=%d..%d",
			socksBase, socksBase+size-1, controlBase, controlBase+size-1),
	}
}

// SetTorPoolSettings persists the pool configuration. When the pool is enabled
// the daemons are (re)started immediately so the change is observable.
func (m *Manager) SetTorPoolSettings(ctx context.Context, enabled bool, size, socksBase, controlBase int, dir, binary, upstream string) error {
	if size < 1 || size > 32 {
		return fmt.Errorf("tor_pool_size 必须在 1..32 之间")
	}
	if socksBase <= 0 || controlBase <= 0 {
		return fmt.Errorf("端口必须为正整数")
	}
	if binary == "" {
		binary = "tor"
	}
	if dir == "" {
		dir = fmt.Sprintf("%s/torpool", m.dir)
	}
	set := map[string]string{
		settingTorPoolOn:          fmt.Sprintf("%t", enabled),
		settingTorPoolSize:        fmt.Sprintf("%d", size),
		settingTorPoolSocksBase:   fmt.Sprintf("%d", socksBase),
		settingTorPoolControlBase: fmt.Sprintf("%d", controlBase),
		settingTorPoolDir:         dir,
		settingTorBinary:          binary,
		settingTorPoolUpstream:    upstream,
	}
	for k, v := range set {
		if err := m.pg.SetSetting(k, v); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.torPoolEnabled = enabled
	m.torPoolSize = size
	m.torPoolSocksBase = socksBase
	m.torPoolControlBase = controlBase
	m.torPoolDir = dir
	m.torBinary = binary
	m.torPoolUpstream = upstream
	m.mu.Unlock()

	return m.StartTorPool(ctx)
}

// validateTorInstance checks a per-agent slot pin. 0 means "auto" and is always
// valid; a positive value must exist in the current pool so a typo cannot
// silently send the agent to another exit.
func (s *Server) validateTorInstance(v int) (int, error) {
	if v < 0 {
		return 0, fmt.Errorf("egress_tor_instance 不能为负")
	}
	if v == 0 {
		return 0, nil
	}
	m := s.m
	m.mu.RLock()
	size := m.torPoolSize
	enabled := m.torPoolEnabled
	m.mu.RUnlock()
	if !enabled {
		return 0, fmt.Errorf("未启用 Tor 实例池，无法固定实例 %d（先在系统设置里开启）", v)
	}
	if v > size {
		return 0, fmt.Errorf("egress_tor_instance=%d 超出池大小 %d", v, size)
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// getTorPool returns pool status plus the effective per-agent assignment.
func (s *Server) getTorPool(w http.ResponseWriter, r *http.Request) {
	st := s.m.TorPoolStatus()
	// 不再用 pool.Instances() 覆盖 status.instances：原始 Instance 不含
	// running/cookie_ready，覆盖会让 UI 丢掉健康状态。
	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"enabled": st.Enabled,
		"status":  st,
	})
}

// startTorPool (re)starts the daemons from the persisted settings.
func (s *Server) startTorPool(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := s.m.StartTorPool(ctx); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": s.m.TorPoolStatus()})
}

// stopTorPool terminates the daemons; agents with egress_mode=tor then fall back
// to the single shared daemon (or fail closed when none is configured).
func (s *Server) stopTorPool(w http.ResponseWriter, r *http.Request) {
	s.m.StopTorPool()
	writeJSON(w, 200, map[string]any{"ok": true, "status": s.m.TorPoolStatus()})
}

type torPoolSettingsReq struct {
	Enabled     bool   `json:"enabled"`
	Size        int    `json:"size"`
	SocksBase   int    `json:"socks_base"`
	ControlBase int    `json:"control_base"`
	Dir         string `json:"dir"`
	Binary      string `json:"binary"`
	Upstream    string `json:"upstream"`
}

// updateTorPool saves settings and reapplies them.
func (s *Server) updateTorPool(w http.ResponseWriter, r *http.Request) {
	var req torPoolSettingsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := s.m.SetTorPoolSettings(ctx, req.Enabled, req.Size, req.SocksBase, req.ControlBase,
		strings.TrimSpace(req.Dir), strings.TrimSpace(req.Binary), strings.TrimSpace(req.Upstream)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": s.m.TorPoolStatus()})
}
