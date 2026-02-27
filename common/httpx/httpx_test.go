package httpx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	opts := DefaultOptions
	ht, err := New(&opts)
	require.Nil(t, err)

	t.Run("content-length in header", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://scanme.sh", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	})

	t.Run("content-length with binary body", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://www.w3schools.com/images/favicon.ico", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Greater(t, len(resp.Raw), 800)
	})
}

func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	opts := DefaultOptions
	opts.Protocol = HTTP11
	ht, err := New(&opts)
	require.Nil(t, err)

	// When HTTP/1.1 is explicitly selected, the retryablehttp client's
	// HTTPClient2 should be the same instance as HTTPClient so the
	// fallback path in do.go cannot switch to HTTP/2.
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should point to the same client as HTTPClient when protocol is http11")
}

func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	opts := DefaultOptions
	ht, err := New(&opts)
	require.Nil(t, err)

	// With the default protocol (no explicit -pr flag), HTTPClient2
	// should remain a distinct client with HTTP/2 support for fallback.
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should be a separate client when no protocol is specified")
}
