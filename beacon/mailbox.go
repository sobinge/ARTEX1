package beacon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Direction names one side of the dead drop.
type Direction string

const (
	// Outbound carries operator → target frames (commands).
	Outbound Direction = "out"
	// Inbound carries target → operator frames (results, heartbeats).
	Inbound Direction = "in"
)

// Envelope is one frame as stored by a mailbox. Seq lets both peers request
// only what they have not seen yet.
type Envelope struct {
	Seq   uint64 `json:"seq"`
	Frame string `json:"frame"` // hex; opaque to the mailbox
}

// Mailbox is the storage primitive a dead drop needs. Implementations differ
// only in transport (local dir, HTTP relay, object storage), never in what they
// can see: frames are already encrypted before reaching them.
type Mailbox interface {
	// Put stores one envelope. Overwriting the same (channel, direction, seq)
	// must be idempotent.
	Put(ctx context.Context, channel string, dir Direction, env Envelope) error
	// List returns envelopes with seq > since, ascending, at most limit.
	List(ctx context.Context, channel string, dir Direction, since uint64, limit int) ([]Envelope, error)
	// Delete removes the given sequences (already delivered).
	Delete(ctx context.Context, channel string, dir Direction, seqs []uint64) error
}

// ---------- HTTP mailbox ----------
//
// Contract (deliberately tiny so any relay, CDN-fronted endpoint or object-store
// shim can implement it):
//
//	PUT    {base}/{channel}/{dir}/{seq}   body: hex frame
//	GET    {base}/{channel}/{dir}?since=N&limit=M   → {"messages":[{seq,frame}]}
//	DELETE {base}/{channel}/{dir}?seq=N,M,...       → 200
//
// The client is supplied by the caller so onion (socks5h) and CDN (https) share
// one implementation.

// HTTPMailbox talks to a relay over HTTP.
type HTTPMailbox struct {
	Base   string
	Client *http.Client
}

func (m *HTTPMailbox) urlFor(channel string, dir Direction, tail string) string {
	base := strings.TrimRight(m.Base, "/")
	u := base + "/" + url.PathEscape(channel) + "/" + string(dir)
	if tail != "" {
		u += "/" + tail
	}
	return u
}

func (m *HTTPMailbox) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return http.DefaultClient
}

func (m *HTTPMailbox) Put(ctx context.Context, channel string, dir Direction, env Envelope) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		m.urlFor(channel, dir, strconv.FormatUint(env.Seq, 10)), strings.NewReader(env.Frame))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("beacon: mailbox put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("beacon: mailbox put: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (m *HTTPMailbox) List(ctx context.Context, channel string, dir Direction, since uint64, limit int) ([]Envelope, error) {
	u := m.urlFor(channel, dir, "") + fmt.Sprintf("?since=%d&limit=%d", since, limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("beacon: mailbox list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("beacon: mailbox list: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Messages []Envelope `json:"messages"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("beacon: mailbox list decode: %w", err)
	}
	sort.Slice(out.Messages, func(i, j int) bool { return out.Messages[i].Seq < out.Messages[j].Seq })
	return out.Messages, nil
}

func (m *HTTPMailbox) Delete(ctx context.Context, channel string, dir Direction, seqs []uint64) error {
	if len(seqs) == 0 {
		return nil
	}
	parts := make([]string, 0, len(seqs))
	for _, s := range seqs {
		parts = append(parts, strconv.FormatUint(s, 10))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		m.urlFor(channel, dir, "")+"?seq="+strings.Join(parts, ","), nil)
	if err != nil {
		return err
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("beacon: mailbox delete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("beacon: mailbox delete: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---------- file mailbox (tests + single-host relay) ----------

// FileMailbox stores envelopes as files: <root>/<channel>/<dir>/<seq>.frame.
type FileMailbox struct {
	Root string
	mu   sync.Mutex
}

func (m *FileMailbox) dirPath(channel string, dir Direction) string {
	return filepath.Join(m.Root, channel, string(dir))
}

func (m *FileMailbox) Put(_ context.Context, channel string, dir Direction, env Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.dirPath(channel, dir)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d, fmt.Sprintf("%020d.frame", env.Seq)), []byte(env.Frame), 0o600)
}

func (m *FileMailbox) List(_ context.Context, channel string, dir Direction, since uint64, limit int) ([]Envelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, err := os.ReadDir(m.dirPath(channel, dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var seqs []uint64
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".frame")
		if n, err := strconv.ParseUint(name, 10, 64); err == nil && n > since {
			seqs = append(seqs, n)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	if limit > 0 && len(seqs) > limit {
		seqs = seqs[:limit]
	}
	out := make([]Envelope, 0, len(seqs))
	for _, s := range seqs {
		b, err := os.ReadFile(filepath.Join(m.dirPath(channel, dir), fmt.Sprintf("%020d.frame", s)))
		if err != nil {
			continue
		}
		out = append(out, Envelope{Seq: s, Frame: string(b)})
	}
	return out, nil
}

func (m *FileMailbox) Delete(_ context.Context, channel string, dir Direction, seqs []uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range seqs {
		err := os.Remove(filepath.Join(m.dirPath(channel, dir), fmt.Sprintf("%020d.frame", s)))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// ---------- helpers ----------

// FrameToHex / HexToFrame keep the wire representation consistent.
func FrameToHex(frame []byte) string { return hex.EncodeToString(frame) }

// HexToFrame decodes a hex frame and validates its fixed size.
func HexToFrame(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("beacon: frame hex: %w", err)
	}
	if len(b) != Size {
		return nil, ErrShortFrame
	}
	return b, nil
}

// GetterFunc adapts a function into a Mailbox (handy in tests).
type GetterFunc func(ctx context.Context, channel string, dir Direction, since uint64, limit int) ([]Envelope, error)

// BytesReader wraps a byte slice for request bodies without extra allocations.
func BytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
