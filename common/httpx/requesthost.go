package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"golang.org/x/net/idna"
)

// ErrPinnedThroughProxy is the error of a request to a pinned host that would
// go through a proxy, which resolves the host itself.
var ErrPinnedThroughProxy = errors.New("a host pinned to an ip cannot be reached through a proxy")

// requestHost is the host a request is made to: the ip it is pinned to, if
// any, and the ip of the last connection dialed to it.
type requestHost struct {
	name   string
	pinned string
	mu     sync.Mutex
	dialed string
}

// requestHostKey is the context key of the requestHost of WithHost.
type requestHostKey struct{}

// WithHost returns a copy of ctx for requests to host. When ip is set, they
// connect to it, like curl --resolve but on every port of host, while the host
// keeps its name for the Host header and SNI. The ip they are dialed to is
// recorded for DialedIP, while the dialer only keeps the last ip dialed to a
// host by any request. Requests to other hosts, such as redirect targets, are
// resolved as usual and not recorded.
func WithHost(ctx context.Context, host, ip string) context.Context {
	host = canonicalHost(host)
	if ip != "" {
		ctx = fastdialer.WithResolveOverride(ctx, host, ip)
	}
	return context.WithValue(ctx, requestHostKey{}, &requestHost{name: host, pinned: ip})
}

// PinnedContext returns a new context for another request derived from req,
// in which the host of req keeps the ip it is pinned to. The other values of
// the context of req, such as a trace, are not kept.
func PinnedContext(req *http.Request) context.Context {
	return WithHost(context.Background(), req.URL.Hostname(), pinnedIP(req))
}

// DialedIP returns the ip of the last connection dialed to the host of a
// WithHost context, or "" if none was.
func DialedIP(ctx context.Context) string {
	host, ok := ctx.Value(requestHostKey{}).(*requestHost)
	if !ok {
		return ""
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	return host.dialed
}

// hostOf returns the requestHost of ctx if name, however it is spelled, is its
// host, and nil otherwise.
func hostOf(ctx context.Context, name string) *requestHost {
	host, ok := ctx.Value(requestHostKey{}).(*requestHost)
	if !ok || host.name != canonicalHost(name) {
		return nil
	}
	return host
}

// pinnedIP returns the ip the host of req is pinned to in its context, if any.
func pinnedIP(req *http.Request) string {
	if host := hostOf(req.Context(), req.URL.Hostname()); host != nil {
		return host.pinned
	}
	return ""
}

// canonicalHost folds the case, the IDNA form and a trailing dot of host, as
// fastdialer keys its resolve overrides, so that a host matches the requests
// and dials to it however it is spelled.
func canonicalHost(host string) string {
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		host = ascii
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// refusePinned wraps the proxy of a transport so that a request to a pinned
// host fails instead of going through the proxy.
func refusePinned(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(req)
		if proxyURL != nil && pinnedIP(req) != "" {
			return nil, ErrPinnedThroughProxy
		}
		return proxyURL, err
	}
}

// dialFunc dials addr, as net.Dialer.DialContext does.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// recordDialedIP wraps dial to record the ip of a connection to the host of a
// WithHost context. A connection to another host, such as a proxy, is not
// recorded.
func recordDialedIP(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return conn, err
		}
		name, _, _ := net.SplitHostPort(addr)
		if host := hostOf(ctx, name); host != nil {
			ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			host.mu.Lock()
			host.dialed = ip
			host.mu.Unlock()
		}
		return conn, nil
	}
}
