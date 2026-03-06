package httpx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew_HTTP11DisablesRetryableHTTP2Fallback(t *testing.T) {
	opts := DefaultOptions
	opts.Protocol = HTTP11

	ht, err := New(&opts)
	require.NoError(t, err)
	require.NotNil(t, ht)
	require.NotNil(t, ht.client)
	require.NotNil(t, ht.client.HTTPClient)
	require.NotNil(t, ht.client.HTTPClient2)

	// Protocol pinning expectation: when forced to HTTP/1.1, retry fallback should
	// stay on the same client/transport instead of switching to dedicated HTTP/2.
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}
