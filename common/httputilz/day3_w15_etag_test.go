package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithIfNoneMatchETag(t *testing.T) {
	raw := "GET /api/v2/items HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: W/\"67ab2-b88390\"\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/api/v2/items", req.URL.RequestURI())
}
