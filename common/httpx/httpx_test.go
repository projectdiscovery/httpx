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
		resp, err := ht.Do(req, UnsafeOptions{}

func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	// copy default to avoid mutating globals
	opts := DefaultOptions
	opts.Protocol = HTTP11
	ht, err := New(&opts)
	require.NoError(t, err)
	// HTTPClient2 should equal HTTPClient when HTTP11
	require.Equal(t, ht.client.HTTPClient, ht.client.HTTPClient2)
	// probe client should also be the same HTTP/1.1 client
	require.Equal(t, ht.client.HTTPClient, ht.client2)
}

func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	// default protocol (UNKNOWN) should not disable fallback
	opts := DefaultOptions
	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotEqual(t, ht.client.HTTPClient, ht.client.HTTPClient2)
})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	}

func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	// copy default to avoid mutating globals
	opts := DefaultOptions
	opts.Protocol = HTTP11
	ht, err := New(&opts)
	require.NoError(t, err)
	// HTTPClient2 should equal HTTPClient when HTTP11
	require.Equal(t, ht.client.HTTPClient, ht.client.HTTPClient2)
	// probe client should also be the same HTTP/1.1 client
	require.Equal(t, ht.client.HTTPClient, ht.client2)
}

func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	// default protocol (UNKNOWN) should not disable fallback
	opts := DefaultOptions
	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotEqual(t, ht.client.HTTPClient, ht.client.HTTPClient2)
})

	t.Run("content-length with binary body", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://www.w3schools.com/images/favicon.ico", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{}

func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	// copy default to avoid mutating globals
	opts := DefaultOptions
	opts.Protocol = HTTP11
	ht, err := New(&opts)
	require.NoError(t, err)
	// HTTPClient2 should equal HTTPClient when HTTP11
	require.Equal(t, ht.client.HTTPClient, ht.client.HTTPClient2)
	// probe client should also be the same HTTP/1.1 client
	require.Equal(t, ht.client.HTTPClient, ht.client2)
}

func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	// default protocol (UNKNOWN) should not disable fallback
	opts := DefaultOptions
	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotEqual(t, ht.client.HTTPClient, ht.client.HTTPClient2)
})
		require.Nil(t, err)
		require.Greater(t, len(resp.Raw), 800)
	}

func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	// copy default to avoid mutating globals
	opts := DefaultOptions
	opts.Protocol = HTTP11
	ht, err := New(&opts)
	require.NoError(t, err)
	// HTTPClient2 should equal HTTPClient when HTTP11
	require.Equal(t, ht.client.HTTPClient, ht.client.HTTPClient2)
	// probe client should also be the same HTTP/1.1 client
	require.Equal(t, ht.client.HTTPClient, ht.client2)
}

func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	// default protocol (UNKNOWN) should not disable fallback
	opts := DefaultOptions
	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotEqual(t, ht.client.HTTPClient, ht.client.HTTPClient2)
})
}

func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	// copy default to avoid mutating globals
	opts := DefaultOptions
	opts.Protocol = HTTP11
	ht, err := New(&opts)
	require.NoError(t, err)
	// HTTPClient2 should equal HTTPClient when HTTP11
	require.Equal(t, ht.client.HTTPClient, ht.client.HTTPClient2)
	// probe client should also be the same HTTP/1.1 client
	require.Equal(t, ht.client.HTTPClient, ht.client2)
}

func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	// default protocol (UNKNOWN) should not disable fallback
	opts := DefaultOptions
	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotEqual(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}
