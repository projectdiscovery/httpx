package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithOriginHeader(t *testing.T) {
	raw := "OPTIONS /graphql HTTP/1.1\r\nHost: api.example.com\r\nOrigin: https://dashboard.example.com\r\nAccess-Control-Request-Method: POST\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "OPTIONS", req.Method)
}
