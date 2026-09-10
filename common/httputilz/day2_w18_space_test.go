package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithURLPathPercentEncoding(t *testing.T) {
	raw := "GET /api/v1/user%20profile HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/api/v1/user%20profile", req.URL.RequestURI())
}
