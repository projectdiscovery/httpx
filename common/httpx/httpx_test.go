package httpx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	ht, err := New(&DefaultOptions)
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

	// When http11 is requested, HTTPClient2 must point to the same client
	// as HTTPClient so retryablehttp-go's fallback path does not switch to HTTP/2.
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should equal HTTPClient when Protocol is HTTP11")
}

func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	// By default the two clients must remain separate so that the HTTP/2
	// fallback in retryablehttp-go works as designed.
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should differ from HTTPClient by default")
}
