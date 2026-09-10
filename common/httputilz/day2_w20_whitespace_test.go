package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithPaddedHeaderValues(t *testing.T) {
	raw := "GET /status HTTP/1.1\r\nHost:   example.com   \r\nX-Custom-Key:   value123   \r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "example.com", req.Host)
	require.Equal(t, []string{"value123"}, req.Header["X-Custom-Key"])
}
