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
