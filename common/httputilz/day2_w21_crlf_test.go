package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithMultipleCRLFSequences(t *testing.T) {
	raw := "POST /v1/batch HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/v1/batch", req.URL.RequestURI())
}
