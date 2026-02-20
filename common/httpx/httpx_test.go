package httpx

import (
	"net/http"
	"testing"
	"time"

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

func TestHTTP11DisablesRetryHTTP2Fallback(t *testing.T) {
	opts := DefaultOptions
	opts.Timeout = 2 * time.Second
	opts.Protocol = "http11"

	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.NotNil(t, ht.client.HTTPClient)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}

func TestDefaultProtocolKeepsDedicatedHTTP2Client(t *testing.T) {
	opts := DefaultOptions
	opts.Timeout = 2 * time.Second

	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.NotNil(t, ht.client.HTTPClient)
	require.NotNil(t, ht.client.HTTPClient2)
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}
