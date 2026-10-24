package beacon

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// testClient wires a Client to a FileMailbox with a fake runner.
func testClient(t *testing.T) (*Client, *FileMailbox, []byte, string) {
	t.Helper()
	psk, _ := NewPSK()
	mb := &FileMailbox{Root: t.TempDir()}
	const channel = "abc123"
	c, err := NewClient(ClientConfig{
		ChannelID: channel,
		PSK:       psk,
		Mailbox:   mb,
		Interval:  time.Second,
		Runner: func(_ context.Context, cmd string) Result {
			return Result{Code: 0, Stdout: "ran:" + cmd}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, mb, psk, channel
}

// pushCommand seals a command into the outbound mailbox, as the platform would.
func pushCommand(t *testing.T, mb *FileMailbox, psk []byte, channel string, seq uint64, cmd Command) {
	t.Helper()
	payload, _ := json.Marshal(cmd)
	frame, err := Seal(psk, seq, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := mb.Put(context.Background(), channel, Outbound, Envelope{Seq: seq, Frame: FrameToHex(frame)}); err != nil {
		t.Fatal(err)
	}
}

func TestClientCycleRunsCommandAndUploadsResult(t *testing.T) {
	ctx := context.Background()
	c, mb, psk, channel := testClient(t)
	pushCommand(t, mb, psk, channel, 1, Command{Cmd: "whoami", Tag: "t1"})

	var lastIn uint64
	if err := c.Cycle(ctx, &lastIn); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if lastIn != 1 {
		t.Fatalf("lastIn = %d, want 1", lastIn)
	}

	// Command must be consumed (deleted from the outbound mailbox).
	left, _ := mb.List(ctx, channel, Outbound, 0, 10)
	if len(left) != 0 {
		t.Fatalf("command not consumed: %+v", left)
	}

	// The result must be sealed into the inbound mailbox.
	res, _ := mb.List(ctx, channel, Inbound, 0, 10)
	if len(res) != 1 {
		t.Fatalf("results = %+v", res)
	}
	frame, err := HexToFrame(res[0].Frame)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := Open(psk, frame, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got Result
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatal(err)
	}
	if got.Tag != "t1" || got.Stdout != "ran:whoami" {
		t.Fatalf("result = %+v", got)
	}
}

func TestClientIgnoresReplayAfterLastIn(t *testing.T) {
	ctx := context.Background()
	c, mb, psk, channel := testClient(t)
	pushCommand(t, mb, psk, channel, 5, Command{Cmd: "id"})
	var lastIn uint64 = 5 // already handled
	if err := c.Cycle(ctx, &lastIn); err != nil {
		t.Fatal(err)
	}
	res, _ := mb.List(ctx, channel, Inbound, 0, 10)
	if len(res) != 0 {
		t.Fatalf("replayed command must not produce a result: %+v", res)
	}
}

func TestClientJitterStaysInBand(t *testing.T) {
	c, _, _, _ := testClient(t)
	c.cfg.Interval = 100 * time.Second
	c.cfg.Jitter = 0.4
	for i := 0; i < 200; i++ {
		d := c.NextDelay()
		if d < 59*time.Second || d > 141*time.Second {
			t.Fatalf("delay %v out of ±40%% band", d)
		}
	}
}

func TestClientHeartbeatUploadsFrame(t *testing.T) {
	ctx := context.Background()
	c, mb, _, channel := testClient(t)
	if err := c.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	res, _ := mb.List(ctx, channel, Inbound, 0, 10)
	if len(res) != 1 {
		t.Fatalf("heartbeat not stored: %+v", res)
	}
}

func TestValidateChannelID(t *testing.T) {
	for _, ok := range []string{"abc123", "a", "0deadbeef"} {
		if err := ValidateChannelID(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../etc", "ABC", "a/b", "with space"} {
		if err := ValidateChannelID(bad); err == nil {
			t.Errorf("%q accepted, want rejection", bad)
		}
	}
}
