package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"golang.org/x/net/idna"
)

// errPinnedThroughProxy is the error of a request to a pinned host that would
// go through a proxy, which resolves the host itself.
var errPinnedThroughProxy = errors.New("a host pinned to an ip cannot be reached through a proxy")

// pinnedHostKey is the context key of a host pinned with WithPinnedIP.
type pinnedHostKey string

// WithPinnedIP returns a copy of ctx in which requests to host connect to ip,
// like curl --resolve. The host keeps its name for the Host header and SNI,
// and requests to other hosts, such as redirect targets, are resolved as usual.
func WithPinnedIP(ctx context.Context, host, ip string) context.Context {
	host = canonicalHost(host)
	ctx = fastdialer.WithResolveOverride(ctx, host, ip)
	return context.WithValue(ctx, pinnedHostKey(host), ip)
}

// PinnedContext returns a new context in which the host of req keeps the ip it
// is pinned to, for another request derived from req. The other values of the
// context of req, such as a trace, are not kept.
func PinnedContext(req *http.Request) context.Context {
	ctx := context.Background()
	if ip := pinnedIP(req); ip != "" {
		ctx = WithPinnedIP(ctx, req.URL.Hostname(), ip)
	}
	return ctx
}

// pinnedIP returns the ip the host of req is pinned to in its context, if any.
func pinnedIP(req *http.Request) string {
	ip, _ := req.Context().Value(pinnedHostKey(canonicalHost(req.URL.Hostname()))).(string)
	return ip
}

// canonicalHost returns host as net/http dials it, so that a pin matches the
// dials to its host however the host is spelled.
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
			return nil, errPinnedThroughProxy
		}
		return proxyURL, err
	}
}
