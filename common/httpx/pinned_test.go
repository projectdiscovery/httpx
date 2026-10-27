package httpx

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRefusePinned(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:3128")
	require.NoError(t, err)
	proxy := refusePinned(http.ProxyURL(proxyURL))
	ctx := WithPinnedIP(context.Background(), "Pinned.Test.", "192.0.2.10")

	pinned, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://pinned.test:8443/", nil)
	require.NoError(t, err)
	_, err = proxy(pinned)
	require.ErrorIs(t, err, errPinnedThroughProxy)

	idn, err := http.NewRequestWithContext(WithPinnedIP(context.Background(), "bücher.test", "192.0.2.10"), http.MethodGet, "https://xn--bcher-kva.test/", nil)
	require.NoError(t, err)
	_, err = proxy(idn)
	require.ErrorIs(t, err, errPinnedThroughProxy, "an IDN host in ASCII form")

	second, err := http.NewRequestWithContext(WithPinnedIP(ctx, "second.test", "192.0.2.11"), http.MethodGet, "https://second.test/", nil)
	require.NoError(t, err)
	_, err = proxy(second)
	require.ErrorIs(t, err, errPinnedThroughProxy, "each host pinned in a context")

	redirect, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://other.test/", nil)
	require.NoError(t, err)
	got, err := proxy(redirect)
	require.NoError(t, err)
	require.Equal(t, proxyURL, got, "a request to another host keeps the proxy")

	got, err = refusePinned(http.ProxyURL(nil))(pinned)
	require.NoError(t, err)
	require.Nil(t, got, "a pinned request without a proxy")
}
