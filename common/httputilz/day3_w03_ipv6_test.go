package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithIPv6HostHeader(t *testing.T) {
	raw := "GET /status HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "[2001:db8::1]:8080", req.Host)
}
