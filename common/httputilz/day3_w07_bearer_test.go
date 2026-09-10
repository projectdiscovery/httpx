package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithBearerAuthorization(t *testing.T) {
	raw := "GET /api/v1/auth HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "api.example.com", req.Host)
}
