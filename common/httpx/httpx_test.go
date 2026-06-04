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

func TestSetCustomHeaders(t *testing.T) {
	h := &HTTPX{Options: &Options{}}

	t.Run("duplicate values preserved in order", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Test": {"one", "two"}})
		require.Equal(t, []string{"one", "two"}, req.Header.Values("X-Test"))
	})

	t.Run("case-variant duplicates are coalesced", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Test": {"one"}, "x-test": {"two"}})
		require.ElementsMatch(t, []string{"one", "two"}, req.Header.Values("X-Test"))
	})

	t.Run("custom header replaces existing value", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("User-Agent", "default-agent")
		h.SetCustomHeaders(req, map[string][]string{"User-Agent": {"custom-agent"}})
		require.Equal(t, []string{"custom-agent"}, req.Header.Values("User-Agent"))
	})

	t.Run("host header sets request host", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"Host": {"custom.host"}})
		require.Equal(t, "custom.host", req.Host)
		require.Empty(t, req.Header.Values("Host"))
	})

	t.Run("multiple distinct headers preserved", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-One": {"1"}, "X-Two": {"2"}})
		require.Equal(t, []string{"1"}, req.Header.Values("X-One"))
		require.Equal(t, []string{"2"}, req.Header.Values("X-Two"))
	})

	t.Run("multiple cookie values preserved", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"Cookie": {"a=1", "b=2"}})
		require.Equal(t, []string{"a=1", "b=2"}, req.Header.Values("Cookie"))
	})

	t.Run("empty value applied as-is", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Empty": {""}})
		require.Equal(t, []string{""}, req.Header.Values("X-Empty"))
	})

	t.Run("unsafe raw header line stored verbatim as key", func(t *testing.T) {
		hu := &HTTPX{Options: &Options{Unsafe: true}}
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		// in unsafe mode the runner stores the whole raw header line as the key
		// with an empty value; it must survive canonicalization untouched
		hu.SetCustomHeaders(req, map[string][]string{"X-Test: one": {""}})
		require.Equal(t, []string{""}, req.Header.Values("X-Test: one"))
	})
}

func TestParseCustomCookies(t *testing.T) {
	options := &Options{CustomHeaders: map[string][]string{"Cookie": {"a=1", "b=2"}}}
	options.parseCustomCookies()
	require.True(t, options.hasCustomCookies())
	require.Len(t, options.customCookies, 2)
}

func TestHTTP11DisablesRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions
	options.Protocol = HTTP11

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}

func TestDefaultProtocolKeepsRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}
