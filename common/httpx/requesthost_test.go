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
	request := func(ctx context.Context, rawURL string) *http.Request {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		require.NoError(t, err)
		return req
	}

	// a pinned host however it is spelled
	for host, rawURL := range map[string]string{"Pinned.Test.": "https://PINNED.test.:8443/", "xn--bcher-kva.test": "https://bücher.test/"} {
		_, err = proxy(request(WithHost(context.Background(), host, "192.0.2.10"), rawURL))
		require.ErrorIs(t, err, ErrPinnedThroughProxy, rawURL)
	}

	pinned := WithHost(context.Background(), "pinned.test", "192.0.2.10")
	got, err := proxy(request(pinned, "https://other.test/"))
	require.NoError(t, err)
	require.Equal(t, proxyURL, got, "a request to another host, as a redirect, keeps the proxy")

	got, err = proxy(request(WithHost(context.Background(), "plain.test", ""), "https://plain.test/"))
	require.NoError(t, err)
	require.Equal(t, proxyURL, got, "a host that is not pinned keeps the proxy")

	got, err = refusePinned(http.ProxyURL(nil))(request(pinned, "https://pinned.test/"))
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
	req, err := h.NewRequestWithContext(WithHost(context.Background(), "pinned.test", "127.0.0.1"), http.MethodGet, "http://pinned.test/")
	require.NoError(t, err)
	_, err = h.Do(req, UnsafeOptions{})
	require.ErrorIs(t, err, ErrPinnedThroughProxy)
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
	ctx := httptrace.WithClientTrace(WithHost(context.Background(), "pinned.test", "192.0.2.10"), &httptrace.ClientTrace{})
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
	ctx := WithHost(context.Background(), "dialed.test", "")

	conn, err := dial(ctx, "tcp", "proxy.test:3128")
	require.NoError(t, err)
	_ = conn.Close()
	require.Empty(t, DialedIP(ctx), "a dial to another host, such as a proxy")

	// net/http dials a host as it is spelled
	conn, err = dial(ctx, "tcp", "DIALED.test.:80")
	require.NoError(t, err)
	_ = conn.Close()
	require.Equal(t, "127.0.0.1", DialedIP(ctx))
}
