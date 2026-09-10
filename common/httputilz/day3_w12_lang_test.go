package httputilz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRequestWithAcceptLanguageLocales(t *testing.T) {
	raw := "GET /intl/home HTTP/1.1\r\nHost: example.com\r\nAccept-Language: en-US,en;q=0.9,fr-CA;q=0.7,fr;q=0.8\r\n\r\n"
	req, err := ParseRequest(raw, false)
	require.Nil(t, err)
	require.NotNil(t, req)
	require.Equal(t, "/intl/home", req.URL.RequestURI())
}
