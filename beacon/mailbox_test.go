package beacon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestFileMailboxPutListDelete(t *testing.T) {
	ctx := context.Background()
	m := &FileMailbox{Root: t.TempDir()}
	for _, s := range []uint64{3, 1, 2} {
		if err := m.Put(ctx, "chan", Outbound, Envelope{Seq: s, Frame: "aa"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.List(ctx, "chan", Outbound, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Seq != 1 || got[2].Seq != 3 {
		t.Fatalf("list order/len wrong: %+v", got)
	}
	after, _ := m.List(ctx, "chan", Outbound, 2, 10)
	if len(after) != 1 || after[0].Seq != 3 {
		t.Fatalf("since filter wrong: %+v", after)
	}
	if err := m.Delete(ctx, "chan", Outbound, []uint64{1, 2}); err != nil {
		t.Fatal(err)
	}
	left, _ := m.List(ctx, "chan", Outbound, 0, 10)
	if len(left) != 1 || left[0].Seq != 3 {
		t.Fatalf("delete wrong: %+v", left)
	}
	// Idempotent put (same seq overrides).
	if err := m.Put(ctx, "chan", Outbound, Envelope{Seq: 3, Frame: "bb"}); err != nil {
		t.Fatal(err)
	}
}

// fakeRelay implements the HTTP contract the adapter expects.
func fakeRelay(t *testing.T) (*httptest.Server, *sync.Map) {
	t.Helper()
	store := &sync.Map{} // key "chan/dir/seq" -> frame
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(parts) < 2 {
			http.NotFound(w, r)
			return
		}
		channel, dir := parts[0], Direction(parts[1])
		switch r.Method {
		case http.MethodPut:
			if len(parts) != 3 {
				http.Error(w, "bad path", 400)
				return
			}
			body, _ := io.ReadAll(r.Body)
			store.Store(channel+"/"+string(dir)+"/"+parts[2], string(body))
			w.WriteHeader(200)
		case http.MethodGet:
			since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
			var out []Envelope
			store.Range(func(k, v any) bool {
				key := k.(string)
				if !strings.HasPrefix(key, channel+"/"+string(dir)+"/") {
					return true
				}
				seqStr := strings.TrimPrefix(key, channel+"/"+string(dir)+"/")
				seq, _ := strconv.ParseUint(seqStr, 10, 64)
				if seq > since {
					out = append(out, Envelope{Seq: seq, Frame: v.(string)})
				}
				return true
			})
			json.NewEncoder(w).Encode(map[string]any{"messages": out})
		case http.MethodDelete:
			for _, s := range strings.Split(r.URL.Query().Get("seq"), ",") {
				store.Delete(channel + "/" + string(dir) + "/" + s)
			}
			w.WriteHeader(200)
		}
	})
	return httptest.NewServer(mux), store
}

func TestHTTPMailboxRoundTrip(t *testing.T) {
	srv, _ := fakeRelay(t)
	defer srv.Close()
	ctx := context.Background()
	m := &HTTPMailbox{Base: srv.URL, Client: srv.Client()}

	psk, _ := NewPSK()
	frame, err := Seal(psk, 7, []byte("whoami"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Put(ctx, "abc", Outbound, Envelope{Seq: 7, Frame: FrameToHex(frame)}); err != nil {
		t.Fatalf("put: %v", err)
	}
	envs, err := m.List(ctx, "abc", Outbound, 0, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(envs) != 1 || envs[0].Seq != 7 {
		t.Fatalf("list = %+v", envs)
	}
	raw, err := hex.DecodeString(envs[0].Frame)
	if err != nil {
		t.Fatal(err)
	}
	plain, seq, err := Open(psk, raw, 0)
	if err != nil || seq != 7 || string(plain) != "whoami" {
		t.Fatalf("open: %q seq=%d err=%v", plain, seq, err)
	}
	if err := m.Delete(ctx, "abc", Outbound, []uint64{7}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	envs, _ = m.List(ctx, "abc", Outbound, 0, 10)
	if len(envs) != 0 {
		t.Fatalf("not deleted: %+v", envs)
	}
}

func TestHexToFrameRejectsWrongSize(t *testing.T) {
	if _, err := HexToFrame("aabb"); err == nil {
		t.Fatal("short frame must be rejected")
	}
}
