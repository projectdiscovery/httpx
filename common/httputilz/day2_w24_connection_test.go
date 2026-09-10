package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithConnectionKeepAlive(t *testing.T) {
	raw := "GET /api/heartbeat HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5, max=1000\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/api/heartbeat", req.URL.RequestURI())
	require.Equal(t, "example.com", req.Host)
}
