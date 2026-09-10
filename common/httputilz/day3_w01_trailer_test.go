package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithChunkedTransferEncodingTrailer(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: Expires\r\n\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/upload", req.URL.RequestURI())
}
