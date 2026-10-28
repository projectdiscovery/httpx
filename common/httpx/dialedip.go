package httpx

import (
	"context"
	"net"
	"sync"
)

// dialFunc dials addr, as net.Dialer.DialContext does.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// dialedIPKey is the context key of the dialedIP of WithDialedIP.
type dialedIPKey struct{}

// dialedIP is the ip of the last connection dialed to a host.
type dialedIP struct {
	host string
	mu   sync.Mutex
	ip   string
}

// WithDialedIP returns a copy of ctx that records the ip of the connections
// dialed to host, for DialedIP. The dialer only keeps the last ip dialed to a
// host by any request, which may be another request's.
func WithDialedIP(ctx context.Context, host string) context.Context {
	return context.WithValue(ctx, dialedIPKey{}, &dialedIP{host: canonicalHost(host)})
}

// DialedIP returns the ip of the last connection dialed to the host of a
// WithDialedIP context, or "" if none was.
func DialedIP(ctx context.Context) string {
	dialed, ok := ctx.Value(dialedIPKey{}).(*dialedIP)
	if !ok {
		return ""
	}
	dialed.mu.Lock()
	defer dialed.mu.Unlock()
	return dialed.ip
}

// recordDialedIP wraps dial to record the ip of a connection to the host of a
// WithDialedIP context. A connection to another host, such as a proxy, is not
// recorded.
func recordDialedIP(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		dialed, ok := ctx.Value(dialedIPKey{}).(*dialedIP)
		if err != nil || !ok {
			return conn, err
		}
		host, _, _ := net.SplitHostPort(addr)
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if canonicalHost(host) == dialed.host && ip != "" {
			dialed.mu.Lock()
			dialed.ip = ip
			dialed.mu.Unlock()
		}
		return conn, err
	}
}
