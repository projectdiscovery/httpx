package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithSecFetchHeaders(t *testing.T) {
	raw := "GET /static/image.png HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Dest: image\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Site: same-origin\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/static/image.png", req.URL.RequestURI())
}
