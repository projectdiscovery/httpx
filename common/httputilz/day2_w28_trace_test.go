package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithTraceMethod(t *testing.T) {
	raw := "TRACE / HTTP/1.1\r\nHost: example.com\r\nMax-Forwards: 10\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "TRACE", req.Method)
	require.Equal(t, "/", req.URL.RequestURI())
}
