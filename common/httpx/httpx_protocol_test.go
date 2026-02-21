package httpx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHTTP11DisablesRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions
	options.Protocol = HTTP11

	h, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, h.client)
	require.Same(t, h.client.HTTPClient, h.client.HTTPClient2)
}

func TestNewDefaultKeepsRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions

	h, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, h.client)
	require.NotSame(t, h.client.HTTPClient, h.client.HTTPClient2)
}
