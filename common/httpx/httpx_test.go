package httpx

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestHTTP11DisablesHTTP2Fallback verifies that setting Protocol to HTTP11
// causes the retryablehttp client's HTTPClient2 to be the same as HTTPClient,
// preventing retryablehttp-go from silently upgrading to HTTP/2 on malformed
// HTTP version errors.
func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	// New() sets GODEBUG=http2client=0 for HTTP11 — isolate this side effect
	originalGodebug, hadGodebug := os.LookupEnv("GODEBUG")
	t.Cleanup(func() {
		if hadGodebug {
			os.Setenv("GODEBUG", originalGodebug)
		} else {
			os.Unsetenv("GODEBUG")
		}
	})

	opts := Options{
		Timeout:  5 * time.Second,
		RetryMax: 1,
		Protocol: HTTP11,
	}
	ht, err := New(&opts)
	require.Nil(t, err)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should be the same as HTTPClient when Protocol is HTTP11, preventing HTTP/2 fallback")
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
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should be a separate client from HTTPClient when Protocol is not HTTP11")
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
