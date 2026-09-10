package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithContentLengthZero(t *testing.T) {
	raw := "POST /api/v1/ping HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, int64(0), req.ContentLength)
}
