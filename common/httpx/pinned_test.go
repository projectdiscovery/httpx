package httpx

import (
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRefusePinned(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:3128")
	require.NoError(t, err)
	proxy := refusePinned(http.ProxyURL(proxyURL))
	ctx := WithPinnedIP(WithPinnedIP(context.Background(), "Pinned.Test.", "192.0.2.10"), "second.test", "192.0.2.11")

	for _, rawURL := range []string{"https://pinned.test:8443/", "https://second.test/"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		require.NoError(t, err)
		_, err = proxy(req)
		require.ErrorIs(t, err, errPinnedThroughProxy, "each host pinned in a context")
	}

	redirect, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://other.test/", nil)
	require.NoError(t, err)
	got, err := proxy(redirect)
	require.NoError(t, err)
	require.Equal(t, proxyURL, got, "a request to another host keeps the proxy")

	pinned, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://pinned.test/", nil)
	require.NoError(t, err)
	got, err = refusePinned(http.ProxyURL(nil))(pinned)
	require.NoError(t, err)
	require.Nil(t, got, "a pinned request without a proxy")
}

// A pin matches the host as net/http dials it, however the host is spelled.
func TestCanonicalHost(t *testing.T) {
	for host, want := range map[string]string{
		"Pinned.Test.":       "pinned.test",
		"bücher.test":        "xn--bcher-kva.test",
		"BÜCHER.test":        "xn--bcher-kva.test",
		"bücher。test":        "xn--bcher-kva.test",
		"xn--bcher-kva.test": "xn--bcher-kva.test",
	} {
		require.Equal(t, want, canonicalHost(host), host)
	}
}

func TestPinnedContext(t *testing.T) {
	ctx := httptrace.WithClientTrace(WithPinnedIP(context.Background(), "pinned.test", "192.0.2.10"), &httptrace.ClientTrace{})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://pinned.test/favicon.ico", nil)
	require.NoError(t, err)

	derived := req.Clone(PinnedContext(req))
	require.Equal(t, "192.0.2.10", pinnedIP(derived), "the pin is kept")
	require.Nil(t, httptrace.ContextClientTrace(derived.Context()), "the trace is not")

	other, err := http.NewRequest(http.MethodGet, "https://other.test/", nil)
	require.NoError(t, err)
	require.Empty(t, pinnedIP(other.Clone(PinnedContext(other))))
}

func TestRecordDialedIP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	// every address is dialed to the listener
	dial := recordDialedIP(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	})
	ctx := WithDialedIP(context.Background(), "Dialed.Test")

	conn, err := dial(ctx, "tcp", "proxy.test:3128")
	require.NoError(t, err)
	_ = conn.Close()
	require.Empty(t, DialedIP(ctx), "a dial to another host, such as a proxy")

	conn, err = dial(ctx, "tcp", "dialed.test:80")
	require.NoError(t, err)
	_ = conn.Close()
	require.Equal(t, "127.0.0.1", DialedIP(ctx))

	conn, err = dial(context.Background(), "tcp", "dialed.test:80")
	require.NoError(t, err)
	_ = conn.Close()
	require.Empty(t, DialedIP(context.Background()), "a context without WithDialedIP")
}
