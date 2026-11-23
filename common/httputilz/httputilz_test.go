package httputilz

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestPreservesDuplicateHeaders(t *testing.T) {
	raw := strings.Join([]string{
		"GET /anything HTTP/1.1",
		"Host: example.com",
		"X-Test: one",
		"X-Test: two",
		"",
		"",
	}, "\r\n")

	method, path, headers, _, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.Equal(t, "GET", method)
	require.Equal(t, "/anything", path)
	require.Equal(t, []string{"one", "two"}, headers["X-Test"])
}

func TestParseRequestFullURLPathSetsHost(t *testing.T) {
	raw := strings.Join([]string{
		"GET https://example.com/anything HTTP/1.1",
		"Host: ignored.example",
		"",
		"",
	}, "\r\n")

	_, path, headers, _, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.Equal(t, "https://example.com/anything", path)
	require.Equal(t, []string{"example.com"}, headers["Host"])
}

func TestParseRequestParsesBody(t *testing.T) {
	raw := strings.Join([]string{
		"POST /submit HTTP/1.1",
		"Host: example.com",
		"Content-Type: application/json",
		"",
		`{"a":1}`,
	}, "\r\n")

	method, path, headers, body, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.Equal(t, "POST", method)
	require.Equal(t, "/submit", path)
	require.Equal(t, []string{"application/json"}, headers["Content-Type"])
	require.Equal(t, `{"a":1}`, body)
}

func TestParseRequestSafeStripsContentLength(t *testing.T) {
	raw := strings.Join([]string{
		"GET /anything HTTP/1.1",
		"Host: example.com",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")

	_, _, headers, _, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.NotContains(t, headers, "Content-Length")
}

func TestParseRequestUnsafePreservesRawHeaders(t *testing.T) {
	raw := strings.Join([]string{
		"GET /anything HTTP/1.1",
		"Host: example.com",
		"Content-Length: 0",
		"X-Test: one",
		"X-Test: two",
		"",
		"",
	}, "\r\n")

	_, _, headers, _, err := ParseRequest(raw, true)
	require.NoError(t, err)
	// unsafe mode keeps content-length and does not trim values
	require.Contains(t, headers, "Content-Length")
	require.Equal(t, []string{" one", " two"}, headers["X-Test"])
}

func TestParseRequestMalformed(t *testing.T) {
	_, _, _, _, err := ParseRequest("GET\r\n\r\n", false)
	require.Error(t, err)
}

func TestParseRequestWithoutTrailingNewline(t *testing.T) {
	raw := "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Api-Key: secret"

	method, path, headers, body, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.Equal(t, "GET", method)
	require.Equal(t, "/admin", path)
	require.Equal(t, []string{"127.0.0.1"}, headers["Host"])
	require.Equal(t, []string{"secret"}, headers["X-Api-Key"])
	require.Empty(t, body)
}

func TestParseRequestWithoutTrailingNewlineLF(t *testing.T) {
	raw := "GET /admin HTTP/1.1\nHost: 127.0.0.1\nX-Api-Key: secret"

	method, path, headers, body, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.Equal(t, "GET", method)
	require.Equal(t, "/admin", path)
	require.Equal(t, []string{"127.0.0.1"}, headers["Host"])
	require.Equal(t, []string{"secret"}, headers["X-Api-Key"])
	require.Empty(t, body)
}

func TestParseRequestWithoutTrailingNewlineUnsafe(t *testing.T) {
	raw := "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Api-Key: secret"

	method, path, headers, body, err := ParseRequest(raw, true)
	require.NoError(t, err)
	require.Equal(t, "GET", method)
	require.Equal(t, "/admin", path)
	require.Equal(t, []string{" 127.0.0.1"}, headers["Host"])
	require.Equal(t, []string{" secret"}, headers["X-Api-Key"])
	require.Empty(t, body)
}

func TestParseRequestSingleRequestLineWithoutTrailingNewline(t *testing.T) {
	raw := "GET /admin HTTP/1.1"

	method, path, headers, body, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.Equal(t, "GET", method)
	require.Equal(t, "/admin", path)
	require.Empty(t, headers)
	require.Empty(t, body)
}

func TestParseRequestSafeStripsContentLengthWithoutTrailingNewline(t *testing.T) {
	raw := "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0"

	method, path, headers, body, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.Equal(t, "GET", method)
	require.Equal(t, "/admin", path)
	require.Equal(t, []string{"127.0.0.1"}, headers["Host"])
	require.NotContains(t, headers, "Content-Length")
	require.Empty(t, body)
}

func TestParseRequestMultipleHeadersWithoutTrailingNewline(t *testing.T) {
	raw := "GET /api HTTP/1.1\r\nHost: example.com\r\nX-Header-One: 1\r\nX-Header-Two: 2\r\nX-Last-Header: final"

	method, path, headers, body, err := ParseRequest(raw, false)
	require.NoError(t, err)
	require.Equal(t, "GET", method)
	require.Equal(t, "/api", path)
	require.Equal(t, []string{"example.com"}, headers["Host"])
	require.Equal(t, []string{"1"}, headers["X-Header-One"])
	require.Equal(t, []string{"2"}, headers["X-Header-Two"])
	require.Equal(t, []string{"final"}, headers["X-Last-Header"])
	require.Empty(t, body)
}
