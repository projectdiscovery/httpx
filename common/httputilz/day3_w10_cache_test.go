package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithCacheControlDirectives(t *testing.T) {
	raw := "GET /static/bundle.js HTTP/1.1\r\nHost: example.com\r\nCache-Control: public, max-age=31536000, immutable\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/static/bundle.js", req.URL.RequestURI())
}
