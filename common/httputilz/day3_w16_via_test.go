package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithViaProxyHeader(t *testing.T) {
	raw := "GET /healthz HTTP/1.1\r\nHost: example.com\r\nVia: 1.1 vegur, 2.0 varnish-cache\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "example.com", req.Host)
}
