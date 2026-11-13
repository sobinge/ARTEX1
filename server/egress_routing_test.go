package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/egressroute"
)

func TestRoutingPlatformExceptionPrecedesExplicitBinding(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			var hits atomic.Int32
			targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Error("routing credentials leaked to platform")
				}
				fmt.Fprint(w, "platform reached")
			})
			var target *httptest.Server
			if scheme == "https" {
				target = httptest.NewTLSServer(targetHandler)
			} else {
				target = httptest.NewServer(targetHandler)
			}
			defer target.Close()
			var proxyResolutions atomic.Int32
			router, err := egressroute.New(egressroute.DefaultConfig(), func(context.Context, egressroute.Binding, egressroute.Provider) (string, error) {
				proxyResolutions.Add(1)
				return "", fmt.Errorf("target proxy must not handle platform exceptions")
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			rt := &egressRuntime{
				m:        &Manager{},
				router:   router,
				bindings: map[string]egressroute.Binding{"task-context": {Mode: "direct"}},
				platform: map[string]string{},
			}
			gateway := httptest.NewServer(rt.gatewayHandler())
			defer gateway.Close()
			proxy, _ := url.Parse(gateway.URL)
			proxy.User = url.UserPassword("task-context", "route")
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			response, err := client.Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || string(body) != "platform reached" {
				t.Fatalf("platform failed: HTTP %d, body %q, error %v", response.StatusCode, body, err)
			}
			if hits.Load() != 1 || proxyResolutions.Load() != 0 {
				t.Fatalf("platform hits=%d, target proxy resolutions=%d", hits.Load(), proxyResolutions.Load())
			}

			// Invalid authentication still cannot invoke even a platform exception.
			proxy.User = url.UserPassword("unregistered-context", "route")
			invalidTransport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
			defer invalidTransport.CloseIdleConnections()
			response, err = (&http.Client{Transport: invalidTransport}).Get(target.URL)
			if response != nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != http.StatusProxyAuthRequired {
					t.Fatalf("invalid authentication status = %d", response.StatusCode)
				}
			} else if err == nil {
				t.Fatal("invalid authentication accepted")
			}
			if hits.Load() != 1 {
				t.Fatal("unauthenticated platform request reached target")
			}
		})
	}
}

func TestRoutingPlatformAddressUsesOnlyPinnedOrLiteralExceptions(t *testing.T) {
	rt := &egressRuntime{platform: map[string]string{"api.platform.example": "203.0.113.8"}}
	for _, test := range []struct {
		target, destination string
		allowed             bool
	}{
		{"https://api.platform.example/resource", "203.0.113.8:443", true},
		{"http://API.PLATFORM.EXAMPLE.:8080/", "203.0.113.8:8080", true},
		{"http://127.0.0.1:8787/", "127.0.0.1:8787", true},
		{"http://192.168.1.3/", "192.168.1.3:80", true},
		{"https://[::1]/", "[::1]:443", true},
		{"https://203.0.113.9/", "", false},
		{"http://unlisted.example/", "", false},
		{"https://api.platform.example.attacker.example/", "", false},
	} {
		t.Run(test.target, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			address, allowed := rt.platformAddress(request)
			if address != test.destination || allowed != test.allowed {
				t.Fatalf("platformAddress = %q, %t; want %q, %t", address, allowed, test.destination, test.allowed)
			}
		})
	}
}

func TestRoutingProbeRejectsMissingProxyAndRedirects(t *testing.T) {
	if _, err := egressProbeClient(EgressPlan{Mode: "tor"}); err == nil {
		t.Fatal("target egress probe accepted an empty proxy")
	}
	var redirectedHits atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedHits.Add(1)
		fmt.Fprint(w, `{"IP":"203.0.113.5","IsTor":false}`)
	}))
	defer redirected.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirected.URL, http.StatusFound)
	}))
	defer proxy.Close()
	probe := probeRoutingURL(context.Background(), EgressPlan{Mode: "tor", ProxyURL: proxy.URL}, "http://initial.example/ip")
	if probe.Error == "" || probe.IP != "" {
		t.Fatalf("redirect should be refused, got %+v", probe)
	}
	if !strings.Contains(probe.Error, "302") {
		t.Fatalf("redirect error should identify HTTP status, got %q", probe.Error)
	}
	if redirectedHits.Load() != 0 {
		t.Fatal("probe followed a redirect away from the route being tested")
	}
}
