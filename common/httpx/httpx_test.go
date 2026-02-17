package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	t.Run("content-length in header", func(t *testing.T) {
		// Use a local httptest server to avoid external network dependency
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "2")
			w.Write([]byte("ok"))
		}))
		defer ts.Close()

		req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	})
}

// TestHTTP11DisablesHTTP2Fallback verifies that when Protocol is set to "http11",
// retryablehttp's HTTPClient2 is set to the same client as HTTPClient, preventing
// the HTTP/2 fallback path from using a different (HTTP/2-capable) client.
func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	opts := DefaultOptions
	opts.Protocol = "http11"

	ht, err := New(&opts)
	require.Nil(t, err)

	// When http11 is requested, HTTPClient2 must be the same object as HTTPClient
	// so that retryablehttp-go's fallback path does not switch protocols.
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should be the same as HTTPClient when -pr http11 is set")
}

// TestDefaultProtocolKeepsHTTP2Fallback verifies that by default (no explicit
// protocol selection), HTTPClient and HTTPClient2 remain separate clients so
// the HTTP/2 fallback works as intended.
func TestDefaultProtocolKeepsHTTP2Fallback(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	// By default the two clients should be different objects
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
		"HTTPClient2 should be a different client from HTTPClient by default")
}
