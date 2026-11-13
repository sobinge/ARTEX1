package egressroute

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// BindingForRequest authenticates the proxy client and supplies its task/agent
// identity. A server must bind the returned handler to loopback and must not
// trust arbitrary externally supplied task or agent headers.
type BindingForRequest func(*http.Request) (Binding, error)

func (r *Router) Handler(bindingForRequest BindingForRequest) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if bindingForRequest == nil {
			http.Error(w, "proxy authentication is not configured", http.StatusProxyAuthRequired)
			return
		}
		binding, err := bindingForRequest(request)
		if err != nil {
			http.Error(w, "proxy authentication failed", http.StatusProxyAuthRequired)
			return
		}
		if request.Method == http.MethodConnect {
			r.connect(w, request, binding)
			return
		}
		if request.URL == nil || request.URL.Host == "" || request.URL.User != nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") {
			http.Error(w, "proxy requires an absolute HTTP(S) target URL", http.StatusBadRequest)
			return
		}
		out := request.Clone(request.Context())
		out.RequestURI = ""
		out.Host = out.URL.Host
		removeHopHeaders(out.Header)
		response, err := r.RoundTripper(binding).RoundTrip(out)
		if err != nil {
			http.Error(w, "egress request refused: "+redactError(err), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		removeHopHeaders(response.Header)
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
}

func (r *Router) connect(w http.ResponseWriter, request *http.Request, binding Binding) {
	if request.Host == "" || request.URL == nil || request.URL.User != nil {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	upstream, _, err := r.DialContext(request.Context(), binding, "tcp", request.Host)
	if err != nil {
		http.Error(w, "egress tunnel refused: "+redactError(err), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT requires HTTP/1.x", http.StatusHTTPVersionNotSupported)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := fmt.Fprint(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	// A client may pipeline the TLS handshake after CONNECT. The buffered
	// reader, rather than the raw client connection, preserves those bytes.
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, buffered)
		closeWrite(upstream)
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	closeWrite(client)
	// Close both ends so an EOF or canceled peer cannot strand the other copy.
	_ = upstream.Close()
	_ = client.Close()
	<-done
}

func closeWrite(connection net.Conn) {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
}

func removeHopHeaders(header http.Header) {
	for _, token := range strings.Split(header.Get("Connection"), ",") {
		if token = strings.TrimSpace(token); token != "" {
			header.Del(token)
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}
