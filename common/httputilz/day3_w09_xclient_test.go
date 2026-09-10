package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithCustomXClientHeaders(t *testing.T) {
	raw := "GET /metrics HTTP/1.1\r\nHost: example.com\r\nX-Client-ID: client-node-091\r\nX-Client-Trace: 88291a0f\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/metrics", req.URL.RequestURI())
}
