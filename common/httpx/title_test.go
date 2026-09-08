package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestCanHaveTitleTag(t *testing.T) {
	tests := []struct {
		mimeType string
		expected bool
	}{
		{"text/html", true},
		{"TEXT/HTML", true},
		{"Text/Html", true},
		{"text/html ", true},
		{" application/xhtml+xml", true},
		{"text/plain", false},
		{"application/json", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.mimeType, func(t *testing.T) {
			require.Equal(t, tt.expected, CanHaveTitleTag(tt.mimeType))
		})
	}
}

func TestExtractTitleDecodesCharset(t *testing.T) {
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 2 * time.Second
	options.RetryMax = 0

	ht, err := New(&options)
	require.Nil(t, err)

	// <title>中文</title> with the title text encoded in GBK
	gbk := []byte{0xd6, 0xd0, 0xce, 0xc4}
	body := append([]byte("<html><head><title>"), gbk...)
	body = append(body, []byte("</title></head></html>")...)

	tests := []struct {
		name        string
		contentType string
	}{
		{"quoted charset", `text/html; charset="gbk"`},
		{"unquoted charset", "text/html; charset=gbk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			req, err := retryablehttp.NewRequest(http.MethodGet, srv.URL, nil)
			require.Nil(t, err)
			resp, err := ht.Do(req, UnsafeOptions{})
			require.Nil(t, err)
			require.Equal(t, "中文", ExtractTitle(resp))
		})
	}
}
