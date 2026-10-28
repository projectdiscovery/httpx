package httpx

import (
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRefusePinned(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:3128")
	require.NoError(t, err)
	proxy := refusePinned(http.ProxyURL(proxyURL))
	ctx := WithPinnedIP(WithPinnedIP(context.Background(), "Pinned.Test.", "192.0.2.10"), "xn--bcher-kva.test", "192.0.2.11")

	// each host pinned in a context, however it is spelled
	for _, rawURL := range []string{"https://PINNED.test.:8443/", "https://bücher.test/"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		require.NoError(t, err)
		_, err = proxy(req)
		require.ErrorIs(t, err, errPinnedThroughProxy, rawURL)
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

// A proxy set in the environment is refused for a pinned request as well. Go
// reads the proxies of the environment once, so the test runs in a new process.
func TestRefusePinned_environment(t *testing.T) {
	if os.Getenv("HTTPX_TEST_ENV_PROXY") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRefusePinned_environment$")
		// the lower case names first: on Windows, the last of two spellings wins
		cmd.Env = append(os.Environ(), "HTTPX_TEST_ENV_PROXY=1", "http_proxy=", "no_proxy=", "NO_PROXY=", "HTTP_PROXY=http://127.0.0.1:1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
		return
	}

	options := DefaultOptions
	options.RetryMax = 0
	h, err := New(&options)
	require.NoError(t, err)
	req, err := h.NewRequestWithContext(WithPinnedIP(context.Background(), "pinned.test", "127.0.0.1"), http.MethodGet, "http://pinned.test/")
	require.NoError(t, err)
	_, err = h.Do(req, UnsafeOptions{})
	require.ErrorContains(t, err, errPinnedThroughProxy.Error())
}

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
	ctx := WithDialedIP(context.Background(), "dialed.test")

	conn, err := dial(ctx, "tcp", "proxy.test:3128")
	require.NoError(t, err)
	_ = conn.Close()
	ip, _ := DialedIP(ctx)
	require.Empty(t, ip, "a dial to another host, such as a proxy")

	// net/http dials a host as it is spelled
	conn, err = dial(ctx, "tcp", "DIALED.test.:80")
	require.NoError(t, err)
	_ = conn.Close()
	ip, _ = DialedIP(ctx)
	require.Equal(t, "127.0.0.1", ip)
}

func TestRecordProxied(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:3128")
	require.NoError(t, err)

	for proxy, want := range map[*url.URL]bool{proxyURL: true, nil: false} {
		ctx := WithDialedIP(context.Background(), "dialed.test")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://dialed.test/", nil)
		require.NoError(t, err)
		_, err = recordProxied(http.ProxyURL(proxy))(req)
		require.NoError(t, err)
		_, proxied := DialedIP(ctx)
		require.Equal(t, want, proxied)
	}
}
