package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithAcceptEncodingQValues(t *testing.T) {
	raw := "GET /assets/logo.svg HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip, deflate, br;q=1.0, *;q=0.5\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/assets/logo.svg", req.URL.RequestURI())
}
