package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithMultipleCookieHeaders(t *testing.T) {
	raw := "GET /dashboard HTTP/1.1\r\nHost: example.com\r\nCookie: session_id=xyz123\r\nCookie: theme=dark\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/dashboard", req.URL.RequestURI())
}
