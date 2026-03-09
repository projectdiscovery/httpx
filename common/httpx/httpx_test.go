package httpx

import (
	"net/http"
	"os"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestHTTP11ProtocolEnforcement verifies that -pr http11 prevents the retryablehttp-go
// HTTP/2 fallback from bypassing the HTTP/1.1-only restriction (#2240).
func TestHTTP11ProtocolEnforcement(t *testing.T) {
	t.Run("http11 mode disables HTTPClient2 fallback", func(t *testing.T) {
		t.Setenv("GODEBUG", os.Getenv("GODEBUG"))
		opts := DefaultOptions
		opts.Protocol = "http11"
		ht, err := New(&opts)
		require.Nil(t, err)

		// When Protocol == "http11", HTTPClient2 must point to the same underlying
		// client as HTTPClient so the retryablehttp-go fallback is neutralised.
		require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2,
			"HTTPClient2 must equal HTTPClient in http11 mode to prevent HTTP/2 fallback")
	})

	t.Run("default mode keeps distinct HTTPClient2", func(t *testing.T) {
		t.Setenv("GODEBUG", os.Getenv("GODEBUG"))
		ht, err := New(&DefaultOptions)
		require.Nil(t, err)

		// Without an explicit http11 restriction the two clients must differ
		// (HTTPClient2 is the native HTTP/2 client used for protocol detection).
		require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
			"HTTPClient2 must be distinct from HTTPClient in default mode")
	})
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
