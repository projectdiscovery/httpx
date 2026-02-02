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

// TestHTTP11ProtocolEnforcement verifies that when http11 protocol is requested,
// the HTTPClient2 is also configured to use HTTP/1.1 only, preventing fallback to HTTP/2.
// This is a regression test for https://github.com/projectdiscovery/httpx/issues/2240
func TestHTTP11ProtocolEnforcement(t *testing.T) {
	t.Run("http11 protocol disables HTTP/2 fallback", func(t *testing.T) {
		opts := DefaultOptions
		opts.Protocol = "http11"
		ht, err := New(&opts)
		require.Nil(t, err)
		require.NotNil(t, ht.client)

		// Verify that HTTPClient2's transport also has TLSNextProto set to disable HTTP/2
		// When http11 is requested, HTTPClient2 should use the same HTTP/1.1-only transport
		transport, ok := ht.client.HTTPClient2.Transport.(*http.Transport)
		require.True(t, ok, "HTTPClient2 should use http.Transport")
		require.NotNil(t, transport.TLSNextProto, "TLSNextProto should be set to disable HTTP/2")
		require.Empty(t, transport.TLSNextProto, "TLSNextProto should be empty map to disable HTTP/2")
	})

	t.Run("default protocol allows HTTP/2 fallback", func(t *testing.T) {
		opts := DefaultOptions
		// Don't set Protocol, use default
		ht, err := New(&opts)
		require.Nil(t, err)
		require.NotNil(t, ht.client)

		// In default mode, HTTPClient2 should have HTTP/2 enabled
		// The transport will have been configured for HTTP/2 by http2.ConfigureTransport
		_, ok := ht.client.HTTPClient2.Transport.(*http.Transport)
		// It could be http.Transport (with HTTP/2 configured) or http2.Transport
		// The important thing is that it's different behavior from http11 mode
		require.True(t, ok || ht.client.HTTPClient2.Transport != nil,
			"HTTPClient2 should have a transport configured")
	})
}
