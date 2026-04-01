package net

import (
	"context"
	"net"
	"net/http"
)

// contextKeyProxyProtoSSL is used to store whether the PROXY protocol v2 header
// indicates a TLS connection
type contextKeyProxyProtoSSL struct{}

// ProxyProtoSSLFromContext retrieves the SSL/TLS information from PROXY protocol v2
// Returns true if the original connection was TLS, or ok=false if not found
func ProxyProtoSSLFromContext(ctx context.Context) (ssl bool, ok bool) {
	val := ctx.Value(contextKeyProxyProtoSSL{})
	if val == nil {
		return false, false
	}
	ssl, ok = val.(bool)
	return ssl, ok
}

// ProxyProtoTLSHandler is an HTTP middleware that extracts SSL/TLS information
// from PROXY protocol v2 TLVs and stores it in the request context.
// This allows the forwarded headers handler to properly set X-Forwarded-Proto
// based on the original client connection protocol, not the connection to skipper.
type ProxyProtoTLSHandler struct {
	Lookup  func(remoteAddr, localAddr string) (bool, bool) // lookup function for TLV SSL data
	Handler http.Handler
}

func (h *ProxyProtoTLSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Try to look up SSL information from PROXY protocol v2 TLVs
	if h.Lookup != nil {
		if ssl, ok := h.Lookup(r.RemoteAddr, getLocalAddr(r)); ok {
			// Store in request context for forwarded headers handler to use
			ctx := context.WithValue(r.Context(), contextKeyProxyProtoSSL{}, ssl)
			r = r.WithContext(ctx)
		}
	}
	h.Handler.ServeHTTP(w, r)
}

// getLocalAddr extracts the local address from the request
func getLocalAddr(r *http.Request) string {
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return addr.String()
	}
	return ""
}

// ForwardedHeaders sets non-standard X-Forwarded-* Headers
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#proxies and https://github.com/authelia/authelia
type ForwardedHeaders struct {
	// For sets or appends request remote IP to the X-Forwarded-For header
	For bool
	// PrependFor sets or prepends request remote IP to the X-Forwarded-For header, overrides For
	PrependFor bool
	// Host sets X-Forwarded-Host to the request host
	Host bool
	// Method sets the http method as X-Forwarded-Method to the request header
	Method bool
	// Uri sets the path and query as X-Forwarded-Uri header to the request header
	Uri bool
	// Port sets X-Forwarded-Port value, use "auto" to detect from the listener address
	Port string
	// Proto sets X-Forwarded-Proto value, use "auto" to detect from TLS state
	Proto string
}

func (h *ForwardedHeaders) Set(req *http.Request) {
	if (h.For || h.PrependFor) && req.RemoteAddr != "" {
		addr := req.RemoteAddr
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			addr = host
		}

		v := req.Header.Get("X-Forwarded-For")
		if v == "" {
			v = addr
		} else if h.PrependFor {
			v = addr + ", " + v
		} else {
			v = v + ", " + addr
		}
		req.Header.Set("X-Forwarded-For", v)
	}

	if h.Host {
		req.Header.Set("X-Forwarded-Host", req.Host)
	}

	if h.Method {
		req.Header.Set("X-Forwarded-Method", req.Method)
	}

	if h.Uri {
		req.Header.Set("X-Forwarded-Uri", req.RequestURI)
	}

	if h.Port == "auto" {
		if addr, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
			if _, port, err := net.SplitHostPort(addr.String()); err == nil {
				req.Header.Set("X-Forwarded-Port", port)
			}
		}
	} else if h.Port != "" {
		req.Header.Set("X-Forwarded-Port", h.Port)
	}

	if h.Proto == "auto" {
		// Check if we have PROXY protocol v2 SSL information
		if ssl, ok := ProxyProtoSSLFromContext(req.Context()); ok {
			if ssl {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		} else if req.TLS != nil {
			// Fall back to checking TLS state
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
	} else if h.Proto != "" {
		req.Header.Set("X-Forwarded-Proto", h.Proto)
	}
}

type ForwardedHeadersHandler struct {
	Headers ForwardedHeaders
	Exclude IPNets
	Handler http.Handler
}

func (h *ForwardedHeadersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && !h.Exclude.Contain(net.ParseIP(host)) {
		h.Headers.Set(r)
	}
	h.Handler.ServeHTTP(w, r)
}

type ContentLengthHeadersHandler struct {
	Max     int64
	Handler http.Handler
}

func (h *ContentLengthHeadersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Max != 0 && r.ContentLength > h.Max {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}

	h.Handler.ServeHTTP(w, r)
}
