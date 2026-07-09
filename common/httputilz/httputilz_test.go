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
