package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithCustomHTTPVerb(t *testing.T) {
	raw := "PURGE /cache/resource HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "PURGE", req.Method)
	require.Equal(t, "/cache/resource", req.URL.RequestURI())
}
