package runner

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEscapeMarkdown(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "httpx", want: "httpx"},
		{name: "pipe", in: "a|b", want: `a\|b`},
		{name: "backslash", in: `C:\temp`, want: `C:\\temp`},
		{name: "backslash before pipe", in: `left\|right`, want: `left\\\|right`},
		{name: "lf", in: "left\nright", want: "left right"},
		{name: "crlf", in: "left\r\nright", want: "left right"},
		{name: "cr", in: "left\rright", want: "left right"},
		{name: "trailing line ending", in: "value\r\n", want: "value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, escapeMarkdown(tt.in))
		})
	}
}

func TestMarkdownRowKeepsOneRowPerResult(t *testing.T) {
	r := Result{
		Title:      `left\|right`,
		Generator:  "left\rright",
		WebServer:  "left\r\nright",
		StatusCode: 200,
	}

	header := r.MarkdownHeader()
	row := r.MarkdownRow(nil)

	require.True(t, strings.HasSuffix(row, "\n"))
	require.Equal(t, 1, strings.Count(row, "\n"), "result must stay on one table row")
	require.NotContains(t, row, "\r")
	require.Contains(t, row, `| left\\\|right |`)
	require.Contains(t, row, "| left right |")

	headerLine := strings.SplitN(header, "\n", 2)[0]
	require.Equal(t, countMarkdownCells(headerLine), countMarkdownCells(strings.TrimSuffix(row, "\n")))
}

// countMarkdownCells counts the cells of a table row the way GitHub Flavored
// Markdown splits it: a pipe preceded by a backslash belongs to the cell.
func countMarkdownCells(line string) int {
	cells := 0
	for i := 1; i < len(line); i++ {
		if line[i] == '|' && line[i-1] != '\\' {
			cells++
		}
	}
	return cells
}

// Structured values must render like the JSON output, not as Go's %v dump.
func TestFormatMarkdownValue(t *testing.T) {
	ts := time.Date(2026, 11, 19, 18, 16, 24, 700533000, time.UTC)
	tests := []struct {
		name string
		in   any
		want string
	}{
		{name: "strings", in: []string{"a", "b"}, want: "a, b"},
		{name: "ints", in: []int{301, 200}, want: "301, 200"},
		{name: "empty slice", in: []CPEInfo{}, want: ""},
		{name: "nil pointer", in: (*WordPressInfo)(nil), want: ""},
		{name: "pointer to struct", in: &WordPressInfo{Plugins: []string{"akismet"}}, want: `{"plugins":["akismet"]}`},
		{name: "slice of structs", in: []CPEInfo{{Product: "grafana", Vendor: "grafana"}}, want: `[{"product":"grafana","vendor":"grafana"}]`},
		{name: "bytes", in: []byte("png"), want: "cG5n"},
		{name: "time", in: ts, want: "2026-11-19T18:16:24.700533Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, formatMarkdownValue(reflect.ValueOf(tt.in)))
		})
	}
}
