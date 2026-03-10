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

// TestHTTP11ProtocolEnforcement verifies that -pr http11 prevents retryablehttp-go's
// HTTP/2 fallback from bypassing the protocol restriction (#2240).
func TestHTTP11ProtocolEnforcement(t *testing.T) {
	t.Run("http11 mode neutralises HTTPClient2 fallback", func(t *testing.T) {
		opts := DefaultOptions
		opts.Protocol = HTTP11
		ht, err := New(&opts)
		require.Nil(t, err)

		// HTTPClient2 must be the same as HTTPClient so the fallback
		// path still uses HTTP/1.1-only transport.
		require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2,
			"HTTPClient2 must equal HTTPClient in http11 mode to prevent HTTP/2 fallback")
	})

	t.Run("default mode keeps separate HTTPClient2 for HTTP/2", func(t *testing.T) {
		ht, err := New(&DefaultOptions)
		require.Nil(t, err)

		// In default mode the two clients must be distinct — HTTPClient2
		// is the HTTP/2-capable client used for protocol detection/fallback.
		require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
			"HTTPClient2 must differ from HTTPClient in default mode")
	})
}
