package customextract

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Presets run over the raw response, so they must match inside it.
func TestExtractPresetsMatchInsideResponse(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<a href="https://example.com:8443/docs?q=1">docs</a> mail admin@example.com, john+tag@example.technology or 10.1.2.3` + "\n"
	for preset, want := range map[string][]string{
		"url":  {"https://example.com:8443/docs?q=1"},
		"mail": {"admin@example.com", "john+tag@example.technology"},
		"ipv4": {"10.1.2.3"},
	} {
		require.Equal(t, want, ExtractPresets[preset].FindAllString(raw, -1), preset)
	}
}

func TestExtractPresetsTrimTrailingPunctuation(t *testing.T) {
	require.Equal(t, []string{"https://example.com/path"}, ExtractPresets["url"].FindAllString("Visit (https://example.com/path).", -1))
	require.Equal(t, []string{"https://en.wikipedia.org/wiki/Foo_(bar)"}, ExtractPresets["url"].FindAllString("see https://en.wikipedia.org/wiki/Foo_(bar).", -1))
}

func TestExtractPresetsMailApostrophe(t *testing.T) {
	require.Equal(t, []string{"o'brien@example.com"}, ExtractPresets["mail"].FindAllString("contact o'brien@example.com today", -1))
}
