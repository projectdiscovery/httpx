package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithMixedCaseHeaders(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHoSt: example.com\r\nAcCePt: text/html\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "example.com", req.Host)
}
