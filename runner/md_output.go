package runner

import (
	"fmt"
	"net/http"
	"strings"
)

func MarkdownHeader(r Result) string {
	var b strings.Builder
	b.WriteString("| URL | Status | Method | IP | Size | Words | Lines | Title | CDN |")
	b.WriteString("\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|")
	b.WriteString("\n")

	return b.String()
}

func (r Result) MarkdownRow(scanopts *ScanOptions) string {
	var b strings.Builder

	fmt.Fprintf(&b, "| %s | `%d %s` | `%s` | `%s` | %d | %d | %d |",
		escapeMarkdown(r.URL),
		r.StatusCode, http.StatusText(r.StatusCode),
		r.Method,
		r.HostIP,
		r.ContentLength,
		r.Words,
		r.Lines)

	if r.Title != "" {
		fmt.Fprintf(&b, " %s |", escapeMarkdown(r.Title))
	} else {
		b.WriteString(" |")
	}

	if r.CDNName != "" {
		fmt.Fprintf(&b, " `%s` |", r.CDNName)
	} else {
		b.WriteString(" |")
	}

	b.WriteString("\n")
	return b.String()
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"|", "\\|",
		"\n", " ",
	)
	return strings.TrimSpace(replacer.Replace(s))
}
