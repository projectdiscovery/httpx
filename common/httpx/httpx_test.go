package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	t.Run("content-length in header", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "2")
			_, _ = w.Write([]byte("OK"))
		}))
		defer server.Close()

		req, err := retryablehttp.NewRequest(http.MethodGet, server.URL, nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	})

	t.Run("content-length with binary body", func(t *testing.T) {
		binary := make([]byte, 1024)
		for i := range binary {
			binary[i] = byte(i % 256)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1024")
			_, _ = w.Write(binary)
		}))
		defer server.Close()

		req, err := retryablehttp.NewRequest(http.MethodGet, server.URL, nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Greater(t, len(resp.Raw), 800)
		require.Equal(t, len(binary), resp.ContentLength)
	})
}

func TestHTTP11DisablesHTTP2Fallback(t *testing.T) {
	t.Run("http11 protocol pins fallback client", func(t *testing.T) {
		opts := DefaultOptions
		opts.Protocol = HTTP11

		ht, err := New(&opts)
		require.NoError(t, err)
		require.NotNil(t, ht.client)

		// When HTTP/1.1 is requested, the fallback HTTP/2 client must be
		// replaced with the primary (HTTP/1.1-only) client so that
		// retryablehttp never silently upgrades the protocol.
		require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2,
			"HTTPClient2 must equal HTTPClient when protocol is http11")
	})

	t.Run("default protocol keeps separate fallback client", func(t *testing.T) {
		opts := DefaultOptions

		ht, err := New(&opts)
		require.NoError(t, err)
		require.NotNil(t, ht.client)

		// With the default (unset) protocol, the two clients should remain
		// independent so the normal HTTP/2 fallback path is preserved.
		require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2,
			"HTTPClient2 must differ from HTTPClient when protocol is default")
	})
}
