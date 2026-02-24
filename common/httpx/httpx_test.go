package httpx

import (
	"net/http"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestHTTP11DisablesHTTP2Fallback verifies that setting Protocol to HTTP11
// causes the retryablehttp client to have HTTPClient2 set to nil, disabling
// the automatic HTTP/2 fallback on malformed HTTP version errors.
func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	opts := Options{
		Timeout:  5 * time.Second,
		RetryMax: 1,
		Protocol: HTTP11,
	}
	ht, err := New(&opts)
	require.Nil(t, err)
	require.Nil(t, ht.client.HTTPClient2, "HTTPClient2 should be nil when Protocol is HTTP11")
}

// TestDefaultProtocolKeepsHTTP2Fallback verifies that when Protocol is not set,
// the retryablehttp client retains an HTTPClient2 for the HTTP/2 fallback.
func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	opts := Options{
		Timeout:  5 * time.Second,
		RetryMax: 1,
	}
	ht, err := New(&opts)
	require.Nil(t, err)
	require.NotNil(t, ht.client.HTTPClient2, "HTTPClient2 should not be nil when Protocol is not HTTP11")
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
