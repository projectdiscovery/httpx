package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithCacheControlDirectives(t *testing.T) {
	raw := "GET /api/feed HTTP/1.1\r\nHost: example.com\r\nCache-Control: no-cache, no-store, must-revalidate\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/api/feed", req.URL.RequestURI())
}
