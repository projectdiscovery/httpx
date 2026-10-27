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
	ctx = fastdialer.WithResolveOverride(ctx, host, ip)
	return context.WithValue(ctx, pinnedHostKey(canonicalHost(host)), ip)
}

// isPinned reports whether req goes to a host pinned in its context.
func isPinned(req *http.Request) bool {
	return req.Context().Value(pinnedHostKey(canonicalHost(req.URL.Hostname()))) != nil
}

// canonicalHost returns host in the form fastdialer compares hosts in.
func canonicalHost(host string) string {
	if ascii, err := idna.ToASCII(host); err == nil {
		host = ascii
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// refusePinned wraps the proxy of a transport so that a request to a pinned
// host fails instead of going through the proxy.
func refusePinned(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(req)
		if proxyURL != nil && isPinned(req) {
			return nil, errPinnedThroughProxy
		}
		return proxyURL, err
	}
}
