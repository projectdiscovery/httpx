package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithOptionsAsterisk(t *testing.T) {
	raw := "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "OPTIONS", req.Method)
	require.Equal(t, "*", req.URL.RequestURI())
}
