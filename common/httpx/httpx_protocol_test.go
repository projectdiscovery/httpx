package httpx

import (
	"os"
	"testing"

	"golang.org/x/net/http2"

	"github.com/stretchr/testify/require"
)

func TestNew_HTTP11DisablesRetryableHTTP2Fallback(t *testing.T) {
	opts := DefaultOptions
	opts.Protocol = HTTP11

	originalGODEBUG, hadGODEBUG := os.LookupEnv("GODEBUG")
	t.Cleanup(func() {
		if hadGODEBUG {
			_ = os.Setenv("GODEBUG", originalGODEBUG)
		} else {
			_ = os.Unsetenv("GODEBUG")
		}
	})

	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotNil(t, ht)
	t.Cleanup(func() { ht.Dialer.Close() })
	require.NotNil(t, ht.client)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
	require.Same(t, ht.client.HTTPClient, ht.client2)
	_, isHTTP2 := ht.client2.Transport.(*http2.Transport)
	require.False(t, isHTTP2)
}

func TestNew_NonHTTP11KeepsRetryableHTTP2FallbackClient(t *testing.T) {
	opts := DefaultOptions
	opts.Protocol = HTTP2

	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotNil(t, ht)
	t.Cleanup(func() { ht.Dialer.Close() })
	require.NotNil(t, ht.client)
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2)
	require.NotSame(t, ht.client.HTTPClient, ht.client2)
	_, isHTTP2 := ht.client2.Transport.(*http2.Transport)
	require.True(t, isHTTP2)
}
