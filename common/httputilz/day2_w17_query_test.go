package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithMultiValuedQueryParams(t *testing.T) {
	raw := "GET /search?q=test&q=override HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/search?q=test&q=override", req.URL.RequestURI())
}
