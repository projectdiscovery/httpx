package httpx

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"
)

// dialFunc dials addr, as net.Dialer.DialContext does.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// dialedIPKey is the context key of the dialedIP of WithDialedIP.
type dialedIPKey struct{}

// dialedIP is the ip of the last connection dialed to a host, and whether a
// request went through a proxy instead.
type dialedIP struct {
	host    string
	mu      sync.Mutex
	ip      string
	proxied bool
}

// WithDialedIP returns a copy of ctx that records the ip of the connections
// dialed to host, for DialedIP. The dialer only keeps the last ip dialed to a
// host by any request, which may be another request's.
func WithDialedIP(ctx context.Context, host string) context.Context {
	return context.WithValue(ctx, dialedIPKey{}, &dialedIP{host: canonicalHost(host)})
}

// DialedIP returns the ip of the last connection dialed to the host of a
// WithDialedIP context, and whether a request with it went through a proxy,
// which dials the host itself.
func DialedIP(ctx context.Context) (ip string, proxied bool) {
	dialed, ok := ctx.Value(dialedIPKey{}).(*dialedIP)
	if !ok {
		return "", false
	}
	dialed.mu.Lock()
	defer dialed.mu.Unlock()
	return dialed.ip, dialed.proxied
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

// recordProxied wraps the proxy of a transport to record that a request with
// a WithDialedIP context goes through a proxy.
func recordProxied(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(req)
		if dialed, ok := req.Context().Value(dialedIPKey{}).(*dialedIP); ok && proxyURL != nil {
			dialed.mu.Lock()
			dialed.proxied = true
			dialed.mu.Unlock()
		}
		return proxyURL, err
	}
}
