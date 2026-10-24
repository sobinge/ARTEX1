// Package torpool runs N independent Tor daemons so each agent can have its own
// exit, guards and circuit state.
//
// Why a pool: Tor's SIGNAL NEWNYM is process-wide. With a single shared daemon,
// rotating one agent's circuits rotates everyone's — which both leaks a
// correlation signal (all agents change exit at the same moment) and makes
// per-agent pacing impossible. One daemon per slot keeps rotation local.
package torpool

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/tor"
)

// Config describes the pool. Zero values are normalised by validate.
type Config struct {
	Binary              string        // tor executable, default "tor"
	Dir                 string        // root directory for per-instance data
	Size                int           // number of daemons
	SocksBase           int           // socks port of instance 0
	ControlBase         int           // control port of instance 0
	ExitCountry         string        // optional default exit pin (e.g. "sg")
	MaxCircuitDirtiness int           // seconds
	StartupTimeout      time.Duration // per-instance readiness timeout
	// UpstreamProxy routes Tor's own connections through an HTTP CONNECT proxy
	// (host:port). Needed where direct access to guard relays is blocked; empty
	// means Tor dials the network directly.
	UpstreamProxy string
}

// Instance is one Tor daemon.
type Instance struct {
	ID          int    `json:"id"`           // 1-based slot number
	SocksPort   int    `json:"socks_port"`   //
	ControlPort int    `json:"control_port"` //
	SocksAddr   string `json:"socks_addr"`   // 127.0.0.1:port
	ControlAddr string `json:"control_addr"` // 127.0.0.1:port
	CookiePath  string `json:"cookie_path"`  //
	DataDir     string `json:"data_dir"`     //
	TorrcPath   string `json:"torrc_path"`   //

	cmd *exec.Cmd
	// adopted marks a daemon inherited from a previous run (same torrc, still
	// listening). We did not spawn it, so Stop() asks it to shut down over the
	// control port instead of signalling a PID we do not own.
	adopted bool
}

// Running reports whether the daemon process was started by this pool and has
// not exited yet.
func (i *Instance) Running() bool {
	if i == nil {
		return false
	}
	if i.adopted {
		return dialable(i.ControlAddr) == nil
	}
	if i.cmd == nil || i.cmd.Process == nil {
		return false
	}
	// Signal 0 asks the kernel whether the PID still exists. os.Process.Signal(nil)
	// returns "invalid argument" on Unix, so the zero syscall signal is required —
	// with nil this method silently reported every instance as stopped.
	return i.cmd.Process.Signal(syscall.Signal(0)) == nil
}

// Client returns a control-port client for this instance.
func (i *Instance) Client() *tor.Client {
	return &tor.Client{Addr: i.ControlAddr, CookiePath: i.CookiePath}
}

// logger keeps the pool dependency-free for tests while still surfacing events.
var logf = func(string, ...any) {}

// SetLogger routes pool events to the caller's logger (server sets log.Printf).
func SetLogger(f func(string, ...any)) {
	if f != nil {
		logf = f
	}
}

func logger() interface{ Printf(string, ...any) } { return logAdapter{} }

type logAdapter struct{}

func (logAdapter) Printf(format string, args ...any) { logf(format, args...) }

// Pool owns the daemons.
type Pool struct {
	cfg Config

	mu      sync.RWMutex
	insts   []*Instance
	started bool
}

// New validates cfg and builds the (not yet started) instance list.
func New(cfg Config) (*Pool, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("torpool: resolve dir: %w", err)
	}
	cfg.Dir = root
	p := &Pool{cfg: cfg}
	for i := 0; i < cfg.Size; i++ {
		dir := filepath.Join(root, fmt.Sprintf("tor-%02d", i+1))
		p.insts = append(p.insts, &Instance{
			ID:          i + 1,
			SocksPort:   cfg.SocksBase + i,
			ControlPort: cfg.ControlBase + i,
			SocksAddr:   fmt.Sprintf("127.0.0.1:%d", cfg.SocksBase+i),
			ControlAddr: fmt.Sprintf("127.0.0.1:%d", cfg.ControlBase+i),
			CookiePath:  filepath.Join(dir, "control_auth_cookie"),
			DataDir:     filepath.Join(dir, "data"),
			TorrcPath:   filepath.Join(dir, "torrc"),
		})
	}
	return p, nil
}

// Config returns the normalised configuration.
func (p *Pool) Config() Config { return p.cfg }

// Size returns the number of slots.
func (p *Pool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.insts)
}

// Instances returns a copy of the instance slice (pointers are shared).
func (p *Pool) Instances() []*Instance {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Instance, len(p.insts))
	copy(out, p.insts)
	return out
}

// Started reports whether Start succeeded and Stop has not run since.
func (p *Pool) Started() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.started
}

// Start launches every daemon and waits for its SOCKS and control ports.
// All-or-nothing: a failure tears down whatever already started, so callers
// never get a half-working pool that silently sends some agents direct.
func (p *Pool) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return nil
	}
	insts := make([]*Instance, len(p.insts))
	copy(insts, p.insts)
	p.mu.Unlock()

	for _, inst := range insts {
		if err := p.startOne(ctx, inst); err != nil {
			p.Stop()
			return err
		}
	}

	p.mu.Lock()
	p.started = true
	p.mu.Unlock()
	return nil
}

func (p *Pool) startOne(ctx context.Context, inst *Instance) error {
	// Adopt a daemon left behind by a previous platform process: it holds our
	// ports and our DataDirectory, so spawning a second one would fail with
	// "address already in use" and leave the pool looking broken after a restart.
	if cfgFile, ok := p.recogniseOwnDaemon(ctx, inst); ok {
		lc := logger()
		lc.Printf("[torpool] 接管已有实例 %d (%s, torrc=%s)", inst.ID, inst.ControlAddr, cfgFile)
		inst.adopted = true
		inst.cmd = nil
		return nil
	}
	if dialable(inst.SocksAddr) == nil || dialable(inst.ControlAddr) == nil {
		return fmt.Errorf("torpool: 实例 %d 的端口已被占用（%s / %s），"+
			"且无法确认是自有实例（torrc=%s）。请先停止占用该端口的进程",
			inst.ID, inst.SocksAddr, inst.ControlAddr, inst.TorrcPath)
	}
	if err := os.MkdirAll(inst.DataDir, 0o700); err != nil {
		return fmt.Errorf("torpool: mkdir %s: %w", inst.DataDir, err)
	}
	if err := os.WriteFile(inst.TorrcPath, []byte(p.cfg.torrc(*inst)), 0o600); err != nil {
		return fmt.Errorf("torpool: write torrc: %w", err)
	}
	// Keep any existing cookie: deleting it would strip a still-running daemon of
	// the only credential we need to adopt it. Freshness is checked instead.

	logPath := filepath.Join(inst.DataDir, "tor.stdout.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("torpool: open log: %w", err)
	}
	startedAt := time.Now()
	cmd := exec.Command(p.cfg.Binary, "-f", inst.TorrcPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	// Detach from the platform's process group so a platform restart does not
	// kill busy circuits mid-request; Stop() still terminates them explicitly.
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("torpool: start %s: %w", p.cfg.Binary, err)
	}
	logFile.Close()
	inst.cmd = cmd

	readyCtx, cancel := context.WithTimeout(ctx, p.cfg.StartupTimeout)
	defer cancel()
	if err := waitReadySince(readyCtx, inst, startedAt); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		inst.cmd = nil
		return fmt.Errorf("torpool: instance %d not ready (%s): %w", inst.ID, logPath, err)
	}
	return nil
}

// waitReady polls until the daemon can actually route traffic.
//
// Tor opens its SOCKS port long before it can build a circuit (bootstrap takes
// 30–90s), so a TCP dial alone would report "ready" while every request hangs.
// The real signal is GETINFO status/bootstrap-phase reaching PROGRESS=100 over
// the control port.
func waitReady(ctx context.Context, inst *Instance) error {
	return waitReadySince(ctx, inst, time.Time{})
}

// waitReadySince additionally requires the control cookie to have been written at
// or after `since`, so a leftover cookie from a previous run cannot make a
// half-dead daemon look ready.
func waitReadySince(ctx context.Context, inst *Instance, since time.Time) error {
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return fmt.Errorf("timeout waiting for ports: %w", lastErr)
		case <-tick.C:
			if err := dialable(inst.SocksAddr); err != nil {
				lastErr = fmt.Errorf("socks %s: %w", inst.SocksAddr, err)
				continue
			}
			if st, err := os.Stat(inst.CookiePath); err != nil || st.Size() == 0 {
				lastErr = fmt.Errorf("control cookie missing: %s", inst.CookiePath)
				continue
			} else if !since.IsZero() && st.ModTime().Before(since.Add(-2*time.Second)) {
				lastErr = fmt.Errorf("control cookie is stale (%s)", st.ModTime().Format(time.RFC3339))
				continue
			}
			if err := dialable(inst.ControlAddr); err != nil {
				lastErr = fmt.Errorf("control %s: %w", inst.ControlAddr, err)
				continue
			}
			// Bootstrap gate: without it the pool reports ready while requests hang.
			cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
			pct, phase, err := inst.Client().BootstrapProgress(cctx)
			ccancel()
			if err != nil {
				lastErr = fmt.Errorf("bootstrap probe: %w", err)
				continue
			}
			if pct < 100 {
				lastErr = fmt.Errorf("bootstrap %d%% (%s)", pct, phase)
				continue
			}
			return nil
		}
	}
}

// recogniseOwnDaemon reports whether an already-running daemon is ours: same
// control port, readable cookie, and GETINFO config-file pointing at our torrc.
// The config-file check is what stops us from adopting an unrelated Tor.
func (p *Pool) recogniseOwnDaemon(ctx context.Context, inst *Instance) (string, bool) {
	if dialable(inst.ControlAddr) != nil {
		return "", false
	}
	if st, err := os.Stat(inst.CookiePath); err != nil || st.Size() == 0 {
		return "", false
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfgFile, err := inst.Client().ConfigFile(cctx)
	if err != nil {
		return "", false
	}
	if filepath.Clean(cfgFile) != filepath.Clean(inst.TorrcPath) {
		return "", false
	}
	return cfgFile, true
}

func dialable(addr string) error {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}

// Stop terminates every daemon. Idempotent.
func (p *Pool) Stop() {
	p.mu.Lock()
	insts := make([]*Instance, len(p.insts))
	copy(insts, p.insts)
	p.started = false
	p.mu.Unlock()

	var wg sync.WaitGroup
	for _, inst := range insts {
		if inst == nil {
			continue
		}
		if inst.adopted {
			wg.Add(1)
			go func(in *Instance) {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_ = in.Client().Shutdown(cctx)
				cancel()
				in.adopted = false
			}(inst)
			continue
		}
		if inst.cmd == nil || inst.cmd.Process == nil {
			continue
		}
		wg.Add(1)
		go func(in *Instance) {
			defer wg.Done()
			proc := in.cmd.Process
			_ = proc.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() {
				_, _ = proc.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = proc.Kill()
				<-done
			}
			in.cmd = nil
		}(inst)
	}
	wg.Wait()
}

// For picks the instance an agent should use. override is 1-based and wins when
// valid; otherwise the assignment is a stable hash of the agent key so the same
// agent keeps the same exit across restarts (moving exits mid-task would look
// like an account switch to the target).
func (p *Pool) For(agentKey string, override int) *Instance {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.insts) == 0 {
		return nil
	}
	if override >= 1 && override <= len(p.insts) {
		return p.insts[override-1]
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(agentKey))
	return p.insts[int(h.Sum32())%len(p.insts)]
}

// NewNym rotates the circuits of the instance serving agentKey.
func (p *Pool) NewNym(ctx context.Context, agentKey string, override int) (*Instance, error) {
	inst := p.For(agentKey, override)
	if inst == nil {
		return nil, fmt.Errorf("torpool: 无可用实例")
	}
	if err := inst.Client().NewNym(ctx); err != nil {
		return inst, err
	}
	return inst, nil
}

// Reload asks every daemon to re-read its configuration (needed after client
// authorization files change).
func (p *Pool) Reload(ctx context.Context) error {
	var errs []string
	for _, inst := range p.Instances() {
		if err := inst.Client().SignalReload(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("instance %d: %v", inst.ID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("torpool reload: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SetExitCountry pins (or clears) the exit country for one instance.
func (p *Pool) SetExitCountry(ctx context.Context, id int, cc string) error {
	inst := p.Instance(id)
	if inst == nil {
		return fmt.Errorf("torpool: 实例 %d 不存在", id)
	}
	return inst.Client().SetExitCountry(ctx, cc)
}

// Instance returns slot id (1-based) or nil.
func (p *Pool) Instance(id int) *Instance {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if id < 1 || id > len(p.insts) {
		return nil
	}
	return p.insts[id-1]
}

// Status is the JSON shape the UI reads.
type Status struct {
	// Enabled mirrors the persisted tor_pool_enabled flag; Started says whether
	// the daemons are actually up right now.
	Enabled   bool           `json:"enabled"`
	Started   bool           `json:"started"`
	Size      int            `json:"size"`
	Ports     string         `json:"ports"`
	Dir       string         `json:"dir"`
	Binary    string         `json:"binary"`
	Instances []InstanceInfo `json:"instances"`
}

// InstanceInfo is one slot's health view.
type InstanceInfo struct {
	ID          int    `json:"id"`
	SocksAddr   string `json:"socks_addr"`
	ControlAddr string `json:"control_addr"`
	Running     bool   `json:"running"`
	CookieReady bool   `json:"cookie_ready"`
	DataDir     string `json:"data_dir"`
}

// Status snapshots the pool for the API.
func (p *Pool) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	st := Status{
		Started: p.started,
		Size:    len(p.insts),
		Ports:   p.cfg.portSummary(),
		Dir:     p.cfg.Dir,
		Binary:  p.cfg.Binary,
	}
	for _, inst := range p.insts {
		info := InstanceInfo{
			ID:          inst.ID,
			SocksAddr:   inst.SocksAddr,
			ControlAddr: inst.ControlAddr,
			Running:     inst.Running(),
			DataDir:     inst.DataDir,
		}
		if st, err := os.Stat(inst.CookiePath); err == nil && st.Size() > 0 {
			info.CookieReady = true
		}
		st.Instances = append(st.Instances, info)
	}
	return st
}
