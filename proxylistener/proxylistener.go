package proxylistener

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	snet "github.com/zalando/skipper/net"
)

// proxySSLCache is a global, thread-safe cache of SSL information from PROXY protocol v2 TLVs
// keyed by "remoteAddr|localAddr"
var proxySSLCache sync.Map

const (
	defaultReadHeaderTimeout = time.Second // 10s seems too long https://github.com/pires/go-proxyproto/blob/5c8010d2392f09ce18169631c024aceae758335a/protocol.go#L28
	defaultReadBufferSize    = 256         // https://github.com/pires/go-proxyproto/blob/5c8010d2392f09ce18169631c024aceae758335a/protocol.go#L21
)

type Options struct {
	Listener          net.Listener
	ReadHeaderTimeout time.Duration
	ReadBufferSize    int

	AllowListCIDRs []string
	DenyListCIDRs  []string
	SkipListCIDRs  []string
}

func NewListener(opt Options) (net.Listener, error) {
	if opt.ReadHeaderTimeout == 0 {
		opt.ReadHeaderTimeout = defaultReadHeaderTimeout
	}
	if opt.ReadBufferSize == 0 {
		opt.ReadBufferSize = defaultReadBufferSize
	}

	skipSet, err := snet.ParseIPCIDRs(opt.SkipListCIDRs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse skip list: %w", err)
	}
	allowSet, err := snet.ParseIPCIDRs(opt.AllowListCIDRs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allow list: %w", err)
	}
	denySet, err := snet.ParseIPCIDRs(opt.DenyListCIDRs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse deny list: %w", err)
	}

	policyLogic := func(cpo proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		host, _, err := net.SplitHostPort(cpo.Upstream.String())
		if err != nil {
			return proxyproto.REJECT, err
		}

		addr, err := netip.ParseAddr(host)
		if err != nil {
			return proxyproto.REJECT, err
		}

		if denySet.Contains(addr) {
			return proxyproto.REJECT, nil
		}
		if skipSet.Contains(addr) {
			return proxyproto.SKIP, nil
		}
		if allowSet.Contains(addr) {
			return proxyproto.USE, nil
		}

		return proxyproto.REJECT, nil
	}

	pl := &proxyproto.Listener{
		Listener:          opt.Listener,
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		ReadBufferSize:    opt.ReadBufferSize,

		ConnPolicy: policyLogic,
	}

	// Wrap the proxy listener to extract TLV data
	return &tlvExtractorListener{wrapped: pl}, nil
}

// tlvExtractorListener wraps a proxyproto.Listener and extracts TLV SSL information
type tlvExtractorListener struct {
	wrapped net.Listener
}

func (tl *tlvExtractorListener) Accept() (net.Conn, error) {
	conn, err := tl.wrapped.Accept()
	if err != nil {
		return conn, err
	}

	// Try to extract TLV SSL information from proxyproto.Conn
	if pconn, ok := conn.(*proxyproto.Conn); ok {
		if header := pconn.ProxyHeader(); header != nil {
			// Try to extract SSL TLV
			tlvs, err := header.TLVs()
			if err == nil {
				ssl := hasTLVSSL(tlvs)
				// Store SSL state keyed by connection addresses
				key := conn.RemoteAddr().String() + "|" + conn.LocalAddr().String()
				proxySSLCache.Store(key, ssl)
			}
		}
	}

	// Wrap the connection to clean up the cache on close
	return &tlvCacheCleanupConn{conn: conn}, nil
}

func (tl *tlvExtractorListener) Close() error {
	return tl.wrapped.Close()
}

func (tl *tlvExtractorListener) Addr() net.Addr {
	return tl.wrapped.Addr()
}

// tlvCacheCleanupConn wraps a net.Conn and cleans up the TLV cache on close
type tlvCacheCleanupConn struct {
	conn net.Conn
}

func (c *tlvCacheCleanupConn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *tlvCacheCleanupConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *tlvCacheCleanupConn) Close() error {
	// Clean up cache entry
	key := c.conn.RemoteAddr().String() + "|" + c.conn.LocalAddr().String()
	proxySSLCache.Delete(key)
	return c.conn.Close()
}

func (c *tlvCacheCleanupConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *tlvCacheCleanupConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *tlvCacheCleanupConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *tlvCacheCleanupConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *tlvCacheCleanupConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// hasTLVSSL checks if the TLV list contains SSL information (type 0x20)
func hasTLVSSL(tlvs []proxyproto.TLV) bool {
	const PP2_TYPE_SSL = 0x20
	for _, tlv := range tlvs {
		if tlv.Type == PP2_TYPE_SSL {
			return true
		}
	}
	return false
}

// GetProxyProtoSSL retrieves the SSL/TLS state for a given connection
// Returns (ssl, ok) where ssl is true if the connection had SSL TLV data
// and ok is true if the lookup was successful
func GetProxyProtoSSL(remoteAddr, localAddr string) (bool, bool) {
	key := remoteAddr + "|" + localAddr
	val, ok := proxySSLCache.Load(key)
	if !ok {
		return false, false
	}
	ssl, ok := val.(bool)
	return ssl, ok
}
