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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := []byte("OK")
			w.Header().Set("Content-Length", "2")
			_, _ = w.Write(body)
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
	options := DefaultOptions
	options.Protocol = HTTP11

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)

	// When protocol is http11, retryablehttp should not use a separate HTTP/2 fallback client.
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}
