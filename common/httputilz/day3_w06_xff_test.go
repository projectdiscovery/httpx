package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithXForwardedForChain(t *testing.T) {
	raw := "GET /api/v2/user HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.195, 70.41.3.18, 150.172.238.178\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/api/v2/user", req.URL.RequestURI())
}
