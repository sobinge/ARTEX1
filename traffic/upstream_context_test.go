package traffic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// The recorder receives task credentials on the original proxy request. In
// particular, MITM HTTPS requests no longer contain CONNECT's proxy headers.
// Both MITM and transparent tunnels must still select the original task.
func TestUpstreamResolverKeepsOriginalContext(t *testing.T) {
	for _, kind := range []string{"http", "https-mitm", "https-passthrough"} {
		t.Run(kind, func(t *testing.T) {
			var targetHits atomic.Int32
			targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Errorf("task proxy credentials leaked to target: %q", r.Header)
				}
				fmt.Fprint(w, "target reached")
			})
			var target *httptest.Server
			if kind == "http" {
				target = httptest.NewServer(targetHandler)
			} else {
				target = httptest.NewTLSServer(targetHandler)
			}
			defer target.Close()

			var mu sync.Mutex
			upstreamAuth := []string{}
			upstream := contextTestUpstream(t, func(auth string) {
				mu.Lock()
				upstreamAuth = append(upstreamAuth, auth)
				mu.Unlock()
			})
			defer upstream.Close()
			recorder := startContextTestRecorder(t)
			if kind == "https-passthrough" {
				u, _ := url.Parse(target.URL)
				recorder.pass.Store(u.Hostname(), struct{}{})
			}
			seen := []string{}
			recorder.SetUpstreamResolver(func(request *http.Request) (*url.URL, error) {
				auth := request.Header.Get("Proxy-Authorization")
				mu.Lock()
				seen = append(seen, auth)
				mu.Unlock()
				user, password, ok := contextProxyCredentials(auth)
				if !ok || password != "route" {
					return nil, errors.New("missing original context")
				}
				u, _ := url.Parse(upstream.URL)
				u.User = url.UserPassword(user, password)
				return u, nil
			})

			for _, token := range []string{"task-tor", "task-clash"} {
				client, transport := contextTestClient(t, recorder, token, target.Certificate())
				response, err := client.Get(target.URL + "/" + token)
				if err != nil {
					t.Fatalf("%s request: %v", token, err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				transport.CloseIdleConnections()
				if err != nil || response.StatusCode != 200 || string(body) != "target reached" {
					t.Fatalf("%s response: HTTP %d, body %q, error %v", token, response.StatusCode, body, err)
				}
			}
			if got := targetHits.Load(); got != 2 {
				t.Fatalf("target hits = %d, want 2", got)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, token := range []string{"task-tor", "task-clash"} {
				expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(token+":route"))
				if !contextSliceContains(seen, expected) || !contextSliceContains(upstreamAuth, expected) {
					t.Fatalf("context %s missing: resolver=%q, upstream=%q", token, seen, upstreamAuth)
				}
			}
		})
	}
}

func TestUpstreamResolverFailureNeverDialsTarget(t *testing.T) {
	for _, kind := range []string{"http", "https-mitm", "https-passthrough"} {
		t.Run(kind, func(t *testing.T) {
			var targetHits atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				targetHits.Add(1)
				fmt.Fprint(w, "unexpected direct connection")
			})
			var target *httptest.Server
			if kind == "http" {
				target = httptest.NewServer(handler)
			} else {
				target = httptest.NewTLSServer(handler)
			}
			defer target.Close()
			recorder := startContextTestRecorder(t)
			if kind == "https-passthrough" {
				u, _ := url.Parse(target.URL)
				recorder.pass.Store(u.Hostname(), struct{}{})
			}
			var resolverHits atomic.Int32
			recorder.SetUpstreamResolver(func(*http.Request) (*url.URL, error) {
				resolverHits.Add(1)
				return nil, errors.New("selected route unavailable; refuse connection")
			})
			client, transport := contextTestClient(t, recorder, "task-tor", target.Certificate())
			defer transport.CloseIdleConnections()
			response, err := client.Get(target.URL)
			if response != nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode < 400 {
					t.Fatalf("route failure unexpectedly succeeded: HTTP %d", response.StatusCode)
				}
			} else if err == nil {
				t.Fatal("route failure produced neither an error nor response")
			}
			if resolverHits.Load() == 0 {
				t.Fatal("upstream resolver was not consulted")
			}
			if hits := targetHits.Load(); hits != 0 {
				t.Fatalf("target received %d requests after route resolution failed", hits)
			}
		})
	}
}

func startContextTestRecorder(t *testing.T, addons ...mproxy.Addon) *Traffic {
	t.Helper()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	reservation.Close()
	recorder, err := Open(t.TempDir(), address)
	if err != nil {
		t.Fatal(err)
	}
	for _, addon := range addons {
		recorder.proxy.AddAddon(addon)
	}
	started := make(chan error, 1)
	go func() { started <- recorder.Start() }()
	t.Cleanup(func() {
		recorder.proxy.Close()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Error("recorder failed to stop")
		}
		recorder.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			connection.Close()
			return recorder
		}
		select {
		case err := <-started:
			t.Fatalf("recorder failed to start: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("recorder did not become ready")
	return nil
}

func contextTestClient(t *testing.T, recorder *Traffic, token string, targetCert *x509.Certificate) (*http.Client, *http.Transport) {
	t.Helper()
	u, _ := url.Parse(recorder.ProxyAddr())
	u.User = url.UserPassword(token, "route")
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(recorder.CACertPath())
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("recorder CA: %v", err)
	}
	// For passthrough, the test's self-signed target is the TLS peer.
	if targetCert != nil {
		pool.AddCert(targetCert)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}, DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, transport
}

func contextTestUpstream(t *testing.T, seen func(string)) *httptest.Server {
	t.Helper()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen(r.Header.Get("Proxy-Authorization"))
		if r.Method == http.MethodConnect {
			upstream, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(r.Context(), "tcp", r.Host)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			defer upstream.Close()
			client, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer client.Close()
			fmt.Fprint(buffer, "HTTP/1.1 200 Connection Established\r\n\r\n")
			buffer.Flush()
			done := make(chan struct{})
			go func() {
				io.Copy(upstream, buffer)
				upstream.Close()
				close(done)
			}()
			io.Copy(client, upstream)
			client.Close()
			<-done
			return
		}
		out := r.Clone(context.Background())
		out.RequestURI = ""
		out.Header.Del("Proxy-Authorization")
		response, err := transport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	}))
}

func contextProxyCredentials(auth string) (string, string, bool) {
	value, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil || !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	return strings.Cut(string(value), ":")
}

func contextSliceContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
