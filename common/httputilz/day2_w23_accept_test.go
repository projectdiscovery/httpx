package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithMultiValuedAcceptHeaders(t *testing.T) {
	raw := "GET /index HTTP/1.1\r\nHost: example.com\r\nAccept: text/html, application/xhtml+xml, application/xml;q=0.9\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "example.com", req.Host)
}
