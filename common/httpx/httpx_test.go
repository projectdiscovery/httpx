package httpx

import (
	"net/http"
	"os"
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

func TestHTTP11DisablesRetryableHTTP2Fallback(t *testing.T) {
	opts := DefaultOptions
	opts.Protocol = HTTP11

	originalGODEBUG, hadGODEBUG := os.LookupEnv("GODEBUG")
	t.Cleanup(func() {
		if hadGODEBUG {
			if err := os.Setenv("GODEBUG", originalGODEBUG); err != nil {
				t.Fatalf("failed to restore GODEBUG: %v", err)
			}
			return
		}
		if err := os.Unsetenv("GODEBUG"); err != nil {
			t.Fatalf("failed to unset GODEBUG: %v", err)
		}
	})

	ht, err := New(&opts)
	require.NoError(t, err)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}
