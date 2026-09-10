package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithHeadMethod(t *testing.T) {
	raw := "HEAD /assets/bundle.js HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "HEAD", req.Method)
	require.Equal(t, "/assets/bundle.js", req.URL.RequestURI())
}
