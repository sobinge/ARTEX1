package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyEnvEmptyIsNil(t *testing.T) {
	// 直连也要给 CURL_HOME：否则宿主 ~/.curlrc 里钉死的代理会劫持"直连"流量。
	env := proxyEnv("", "")
	got := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			got[kv[:i]] = kv[i+1:]
		}
	}
	dir, ok := got["CURL_HOME"]
	if !ok {
		t.Fatalf("direct egress must still pin curl config, got %v", env)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".curlrc"))
	if err != nil {
		t.Fatalf("read generated .curlrc: %v", err)
	}
	if !strings.Contains(string(b), "noproxy") {
		t.Fatalf("direct .curlrc must disable proxies, got %q", b)
	}
}

func TestProxyEnvSetsAllProxyForSocks5(t *testing.T) {
	// Capture-off egress path: a socks5 proxy, no MITM CA. ALL_PROXY must be set
	// (curl reads socks5 only from there), and no CA vars should appear.
	env := proxyEnv("socks5://10.0.0.1:1080", "")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "all_proxy="} {
		if !has(want) {
			t.Errorf("proxyEnv missing %s: %v", want, env)
		}
	}
	if has("SSL_CERT_FILE=") || has("CURL_CA_BUNDLE=") {
		t.Errorf("proxyEnv without CA must not inject CA vars: %v", env)
	}
}

func TestProxyEnvInjectsCAWhenRecording(t *testing.T) {
	env := proxyEnv("http://127.0.0.1:8788", "/data/ca.pem")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"SSL_CERT_FILE=", "CURL_CA_BUNDLE=", "REQUESTS_CA_BUNDLE=", "NODE_EXTRA_CA_CERTS="} {
		if !has(want) {
			t.Errorf("proxyEnv with CA missing %s: %v", want, env)
		}
	}
}

func TestProxyEnvSocks5UsesRemoteDNS(t *testing.T) {
	// socks5:// makes curl resolve names locally (DNS leak, .onion unreachable).
	// Every proxy var must carry socks5h:// instead.
	env := proxyEnv("socks5://user:pass@10.0.0.1:1080", "")
	for _, e := range env {
		switch {
		case strings.HasPrefix(e, "HTTP_PROXY="), strings.HasPrefix(e, "HTTPS_PROXY="),
			strings.HasPrefix(e, "http_proxy="), strings.HasPrefix(e, "https_proxy="),
			strings.HasPrefix(e, "ALL_PROXY="), strings.HasPrefix(e, "all_proxy="):
			if strings.HasPrefix(e, "HTTP_PROXY=socks5://") || strings.HasPrefix(e, "ALL_PROXY=socks5://") ||
				strings.HasPrefix(e, "http_proxy=socks5://") || strings.HasPrefix(e, "all_proxy=socks5://") ||
				strings.HasPrefix(e, "HTTPS_PROXY=socks5://") || strings.HasPrefix(e, "https_proxy=socks5://") {
				t.Errorf("proxy var kept local-resolution scheme: %q", e)
			}
		}
	}
	want := "ALL_PROXY=socks5h://user:pass@10.0.0.1:1080"
	found := false
	for _, e := range env {
		if e == want {
			found = true
		}
	}
	if !found {
		t.Errorf("missing %q in %v", want, env)
	}
}

func TestRemoteDNSProxyLeavesHTTPAlone(t *testing.T) {
	for _, in := range []string{
		"http://127.0.0.1:8788",
		"https://proxy.example:443",
		"socks5h://10.0.0.1:1080",
		"",
	} {
		if got := remoteDNSProxy(in); got != in {
			t.Errorf("remoteDNSProxy(%q) = %q, want unchanged", in, got)
		}
	}
	if got := remoteDNSProxy("SOCKS5://h:1"); got != "socks5h://h:1" {
		t.Errorf("remoteDNSProxy uppercase = %q", got)
	}
}

// The host may pin a proxy in ~/.curlrc, which beats every *_PROXY env var. The
// generated CURL_HOME is what actually makes an agent's egress stick.
func TestProxyEnvPinsCurlConfig(t *testing.T) {
	env := proxyEnv("socks5h://127.0.0.1:19751", "")
	got := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			got[kv[:i]] = kv[i+1:]
		}
	}
	dir := got["CURL_HOME"]
	if dir == "" {
		t.Fatalf("CURL_HOME missing: %v", env)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".curlrc"))
	if err != nil {
		t.Fatalf("read .curlrc: %v", err)
	}
	if !strings.Contains(string(b), `proxy = "socks5h://127.0.0.1:19751"`) {
		t.Fatalf(".curlrc does not pin the egress: %s", b)
	}
	wb, err := os.ReadFile(got["WGETRC"])
	if err != nil {
		t.Fatalf("read .wgetrc: %v", err)
	}
	if !strings.Contains(string(wb), "use_proxy = on") {
		t.Fatalf(".wgetrc wrong: %s", wb)
	}
}
