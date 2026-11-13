package traffic

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// Exercise go-mitmproxy's shared client as well as the ordinary per-connection
// client. The shared client is used when addons rewrite destinations and has
// normal connection pooling, so a lost response can trigger net/http retries.
type replayTestSeparateClient struct{ mproxy.BaseAddon }

func (*replayTestSeparateClient) Requestheaders(flow *mproxy.Flow) {
	flow.UseSeparateClient = true
}

func TestRecorderNeverReplaysUnsafeRequestsAfterLostResponse(t *testing.T) {
	for _, test := range []struct {
		method, body, key string
	}{
		{http.MethodPost, "write once", "Idempotency-Key"},
		{http.MethodPost, "", "Idempotency-Key"},
		{http.MethodPut, "replace once", "Idempotency-Key"},
		{http.MethodDelete, "", "Idempotency-Key"},
		{http.MethodPatch, "patch once", "X-Idempotency-Key"},
		{http.MethodOptions, "", ""},
	} {
		t.Run(test.method+"/"+test.body, func(t *testing.T) {
			replayTestRequest(t, test.method, test.body, test.key, false)
		})
	}
}

func TestRecorderLostResponseInjectionAllowsSafeGETRetry(t *testing.T) {
	// This control proves that the injected failure reaches a reused connection
	// in net/http's retry path, rather than merely failing a fresh connection.
	replayTestRequest(t, http.MethodGet, "", "", true)
}

func replayTestRequest(t *testing.T, method, body, key string, wantRetry bool) {
	t.Helper()
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			fmt.Fprint(w, "warm")
			return
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil || string(payload) != body {
			t.Errorf("target body = %q, error %v; want %q", payload, err, body)
		}
		if key != "" && r.Header.Get(key) != "preserved-key" {
			t.Errorf("target lost original %s", key)
		}
		if calls.Add(1) == 1 {
			// The target has received the complete operation but its response is
			// lost. Replaying it would duplicate the target-side action.
			connection, _, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr != nil {
				t.Errorf("inject connection failure: %v", hijackErr)
				return
			}
			connection.Close()
			return
		}
		fmt.Fprint(w, "unexpected replay")
	}))
	defer target.Close()
	recorder := startContextTestRecorder(t, &replayTestSeparateClient{})
	proxy, _ := url.Parse(recorder.ProxyAddr())
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	response, err := client.Get(target.URL + "/warm")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	// Prevent retries by the test caller: only the recorder may reconstruct the
	// request body. Even an empty body remains an opaque Reader to net/http.
	request, err := http.NewRequestWithContext(context.Background(), method, target.URL+"/operation", io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		request.Header.Set(key, "preserved-key")
	}
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if wantRetry {
		if calls.Load() != 2 || response.StatusCode != 200 {
			t.Fatalf("safe retry control: calls=%d, status=%d; want 2, 200", calls.Load(), response.StatusCode)
		}
	} else if calls.Load() != 1 || response.StatusCode != http.StatusBadGateway {
		t.Fatalf("unsafe request replayed: calls=%d, status=%d; want 1, 502", calls.Load(), response.StatusCode)
	}
}
