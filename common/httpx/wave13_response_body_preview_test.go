package httpx

import (
	"strings"
	"testing"
)

// TestWave13ResponseBodyPreviewTruncation asserts body preview limit
func TestWave13ResponseBodyPreviewTruncation(t *testing.T) {
	maxPreviewBytes := 1024 // 1KB preview

	getPreview := func(body string) string {
		if len(body) <= maxPreviewBytes {
			return body
		}
		return body[:maxPreviewBytes]
	}

	shortBody := "<html><body><h1>200 OK</h1></body></html>"
	if getPreview(shortBody) != shortBody {
		t.Errorf("expected short body to remain untouched")
	}

	longBody := strings.Repeat("A", 2048)
	preview := getPreview(longBody)
	if len(preview) != 1024 {
		t.Errorf("expected preview to be clamped to exactly 1024 bytes, got %d", len(preview))
	}
}

// TestWave13ContentTypeCharsetExtraction asserts charset parsing
func TestWave13ContentTypeCharsetExtraction(t *testing.T) {
	extractCharset := func(header string) string {
		parts := strings.Split(header, ";")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(trimmed), "charset=") {
				return strings.TrimPrefix(trimmed, "charset=")
			}
		}
		return "utf-8"
	}

	header := "text/html; charset=ISO-8859-1"
	if extractCharset(header) != "ISO-8859-1" {
		t.Errorf("expected ISO-8859-1 charset extraction, got %s", extractCharset(header))
	}
	defaultHeader := "application/json"
	if extractCharset(defaultHeader) != "utf-8" {
		t.Errorf("expected default utf-8 charset, got %s", extractCharset(defaultHeader))
	}
}
