package egressroute

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type transport struct {
	router  *Router
	binding Binding
}

// RoundTripper resolves a route for every request, including requests reissued
// after a redirect by http.Client. It never consults proxy environment variables.
func (r *Router) RoundTripper(binding Binding) http.RoundTripper {
	return &transport{router: r, binding: binding}
}

func (t *transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL == nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") || request.URL.User != nil {
		return nil, fmt.Errorf("only HTTP(S) target URLs without userinfo are supported")
	}
	decision, err := t.router.Select(t.binding, request.URL.Hostname())
	if err != nil {
		return nil, err
	}
	response, updated, err := t.attempt(request, decision)
	if err == nil || request.Context().Err() != nil || !safeMethod(request.Method) {
		return response, err
	}
	// Never replay even a GET carrying a body: body-bearing requests may trigger
	// target behavior and may not expose GetBody for safe reconstruction.
	if request.Body != nil && request.Body != http.NoBody {
		return response, err
	}
	fallback, allowed := t.router.fallback(updated)
	if !allowed {
		return response, err
	}
	response, _, err = t.attempt(request.Clone(request.Context()), fallback)
	return response, err
}

func (t *transport) attempt(request *http.Request, decision Decision) (*http.Response, Decision, error) {
	started := time.Now()
	proxyString, err := t.router.resolver(request.Context(), t.binding, decision.Provider)
	var hint string
	var response *http.Response
	if err == nil {
		var upstream *url.URL
		upstream, err = proxyURL(proxyString)
		if err == nil {
			hint = proxyHint(upstream)
			out := request.Clone(request.Context())
			out.RequestURI = ""
			out.Header.Del("Proxy-Authorization")
			persistent := safeMethod(request.Method) && (request.Body == nil || request.Body == http.NoBody)
			response, err = t.router.proxyTransport(upstream, persistent).RoundTrip(out)
		}
	}
	updated := t.router.result(t.binding, decision, request.Method, started, hint, err)
	return response, updated, err
}

func (r *Router) proxyTransport(upstream *url.URL, persistent bool) *http.Transport {
	key := upstream.String() + "/keepalive=" + strconv.FormatBool(persistent)
	r.mu.Lock()
	defer r.mu.Unlock()
	if tr := r.transports[key]; tr != nil {
		return tr
	}
	u := *upstream
	// net/http's SOCKS implementation always passes the target host to the
	// proxy. Both accepted spellings therefore perform remote DNS resolution.
	if u.Scheme == "socks5h" {
		u.Scheme = "socks5"
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(&u),
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     !persistent,
	}
	r.transports[key] = tr
	return tr
}

// CloseIdleConnections releases pooled upstream connections without stopping
// active requests or tunnels.
func (r *Router) CloseIdleConnections() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, tr := range r.transports {
		tr.CloseIdleConnections()
	}
}

// DialContext opens a target connection through the selected proxy. CONNECT
// fallback is permitted only before handing any target bytes to the caller.
func (r *Router) DialContext(ctx context.Context, binding Binding, network, address string) (net.Conn, Decision, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, Decision{}, fmt.Errorf("egress gateway supports TCP only")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, Decision{}, fmt.Errorf("CONNECT target needs a valid host:port")
	}
	if _, err = normalizeHost(host); err != nil {
		return nil, Decision{}, err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, Decision{}, fmt.Errorf("invalid target port")
	}
	decision, err := r.Select(binding, host)
	if err != nil {
		return nil, decision, err
	}
	connection, updated, err := r.dialAttempt(ctx, binding, decision, address)
	if err == nil || ctx.Err() != nil {
		return connection, updated, err
	}
	if fallback, allowed := r.fallback(updated); allowed {
		return r.dialAttempt(ctx, binding, fallback, address)
	}
	return nil, updated, err
}

func (r *Router) dialAttempt(ctx context.Context, binding Binding, decision Decision, address string) (net.Conn, Decision, error) {
	started := time.Now()
	proxyString, err := r.resolver(ctx, binding, decision.Provider)
	var hint string
	var connection net.Conn
	if err == nil {
		var upstream *url.URL
		upstream, err = proxyURL(proxyString)
		if err == nil {
			hint = proxyHint(upstream)
			connection, err = dialProxy(ctx, upstream, address)
		}
	}
	decision = r.result(binding, decision, http.MethodConnect, started, hint, err)
	return connection, decision, err
}

func dialProxy(ctx context.Context, upstream *url.URL, target string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if upstream.Scheme == "socks5" || upstream.Scheme == "socks5h" {
		var auth *proxy.Auth
		if upstream.User != nil {
			password, _ := upstream.User.Password()
			auth = &proxy.Auth{User: upstream.User.Username(), Password: password}
		}
		proxyDialer, err := proxy.SOCKS5("tcp", proxyAddress(upstream), auth, dialer)
		if err != nil {
			return nil, err
		}
		contextDialer, ok := proxyDialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("SOCKS dialer does not support context cancellation")
		}
		return contextDialer.DialContext(ctx, "tcp", target)
	}
	connection, err := dialer.DialContext(ctx, "tcp", proxyAddress(upstream))
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = connection.SetDeadline(deadline)
	deadlineConnection := connection
	stop := context.AfterFunc(ctx, func() { _ = deadlineConnection.SetDeadline(time.Now()) })
	defer stop()
	if upstream.Scheme == "https" {
		tlsConnection := tls.Client(connection, &tls.Config{ServerName: upstream.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		connection = tlsConnection
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if upstream.User != nil {
		password, _ := upstream.User.Password()
		credentials := upstream.User.Username() + ":" + password
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	if err := request.Write(connection); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("upstream proxy refused target tunnel (HTTP %d)", response.StatusCode)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !stop() {
		return nil, ctx.Err()
	}
	_ = connection.SetDeadline(time.Time{})
	failed = false
	if reader.Buffered() != 0 {
		return &bufferedConn{Conn: connection, reader: reader}, nil
	}
	return connection, nil
}

func proxyAddress(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := "80"
	switch u.Scheme {
	case "https":
		port = "443"
	case "socks5", "socks5h":
		port = "1080"
	}
	return net.JoinHostPort(strings.Trim(u.Hostname(), "[]"), port)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
