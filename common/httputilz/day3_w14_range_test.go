package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithRangeBytesHeader(t *testing.T) {
	raw := "GET /media/stream.mp4 HTTP/1.1\r\nHost: example.com\r\nRange: bytes=1024-2048\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "example.com", req.Host)
}
