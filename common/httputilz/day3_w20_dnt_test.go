package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithDNTHeader(t *testing.T) {
	raw := "GET /privacy/policy HTTP/1.1\r\nHost: example.com\r\nDNT: 1\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/privacy/policy", req.URL.RequestURI())
}
