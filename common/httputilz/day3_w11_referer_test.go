package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithRefererHeader(t *testing.T) {
	raw := "GET /api/v1/session HTTP/1.1\r\nHost: example.com\r\nReferer: https://app.example.com/login?redirect=dashboard\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "example.com", req.Host)
}
