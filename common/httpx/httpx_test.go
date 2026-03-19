package httpx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestHTTP11ProtocolDisablesHTTP2Fallback(t *testing.T) {
	opts := DefaultOptions
	opts.Protocol = HTTP11
	ht, err := New(&opts)
	require.Nil(t, err)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should equal HTTPClient when Protocol is HTTP11")
}

func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should differ from HTTPClient with default protocol")
}

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
