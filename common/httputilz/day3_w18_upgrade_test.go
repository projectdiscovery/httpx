package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithUpgradeInsecureRequests(t *testing.T) {
	raw := "GET /secure/app HTTP/1.1\r\nHost: example.com\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/secure/app", req.URL.RequestURI())
}
