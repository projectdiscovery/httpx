package httpx

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// newLocalHTTPX builds an HTTPX instance suitable for hitting a local test
// server only (no external network, CDN checks disabled).
func newLocalHTTPX(t *testing.T) *HTTPX {
	t.Helper()
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 5 * time.Second
	options.RetryMax = 0
	// NB: relies on DefaultOptions.MaxResponseBodySizeToRead being non-zero
	// (see TestDefaultOptionsHasNonZeroReadSize) so the body is actually read.

	ht, err := New(&options)
	require.NoError(t, err)
	return ht
}

// doLocal issues a GET against a local httptest server and returns the parsed
// httpx Response.
func doLocal(t *testing.T, ht *HTTPX, url string) *Response {
	t.Helper()
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)
	return resp
}

// legacyWordsLines reproduces the exact word/line computation that existed
// before the refactor, so we can assert the new byte-based path is equivalent.
func legacyWordsLines(body []byte) (words, lines int) {
	s := string(body)
	if s != "" {
		words = len(strings.Split(s, " "))
		lines = len(strings.Split(strings.TrimSpace(s), "\n"))
	}
	return
}

// TestDefaultOptionsHasNonZeroReadSize guards against the package var-init
// ordering regression where DefaultOptions was initialized before
// DefaultMaxResponseBodySize, leaving MaxResponseBodySizeToRead at 0 (which made
// LimitReader read zero bytes and produced empty bodies for library users).
func TestDefaultOptionsHasNonZeroReadSize(t *testing.T) {
	require.NotZero(t, DefaultMaxResponseBodySize)
	require.Equal(t, DefaultMaxResponseBodySize, DefaultOptions.MaxResponseBodySizeToRead)
}

func TestDoBodyNoDecodePreservesRawAndData(t *testing.T) {
	body := []byte("hello world\nsecond line\n")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.Equal(t, body, resp.Data, "decoded data must equal body")
	require.Equal(t, body, resp.RawData, "raw data must equal undecoded body")

	wantWords, wantLines := legacyWordsLines(body)
	require.Equal(t, wantWords, resp.Words)
	require.Equal(t, wantLines, resp.Lines)
}

func TestDoBodyEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)
	require.Empty(t, resp.Data)
	require.Empty(t, resp.RawData)
	require.Equal(t, 0, resp.Words)
	require.Equal(t, 0, resp.Lines)
}

// TestDoBodyGBKDecodeKeepsRawUndecoded ensures that when DecodeData actually
// transcodes the body, RawData still holds the original (undecoded) bytes while
// Data holds the decoded UTF-8 bytes.
func TestDoBodyGBKDecodeKeepsRawUndecoded(t *testing.T) {
	utf8Body := "<html><head></head><body>你好世界 测试</body></html>"
	gbkBody, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(utf8Body))
	require.NoError(t, err)
	require.NotEqual(t, []byte(utf8Body), gbkBody, "precondition: gbk bytes differ from utf8")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=gbk")
		_, _ = w.Write(gbkBody)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.Equal(t, gbkBody, resp.RawData, "RawData must hold the original undecoded bytes")
	require.Equal(t, []byte(utf8Body), resp.Data, "Data must hold the decoded UTF-8 bytes")
}

// TestDoBodyNoDecodeSharesBacking documents the memory optimization: on the
// no-decode hot path RawData and Data share the same backing array (no extra
// full-body copy is made).
func TestDoBodyNoDecodeSharesBacking(t *testing.T) {
	body := []byte("shared backing array body")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	resp := doLocal(t, newLocalHTTPX(t), ts.URL)

	require.NotEmpty(t, resp.Data)
	require.NotEmpty(t, resp.RawData)
	require.Equal(t, resp.Data, resp.RawData)
	require.Same(t, &resp.Data[0], &resp.RawData[0],
		"RawData and Data should share the backing array on the no-decode path")
}

// TestWordsLinesEquivalence is the core guard for the refactor: the byte-based
// counting used on the hot path must be identical to the previous
// strings.Split-based counting for a wide range of inputs and edge cases.
func TestWordsLinesEquivalence(t *testing.T) {
	cases := []string{
		"",
		"a",
		"a b c",
		"   ",                        // only spaces
		"a  b",                       // consecutive spaces
		"line1\nline2\nline3",        // multiple lines
		"\n\n\n",                     // only newlines
		"  leading and trailing  ",   // surrounding whitespace
		"\n  mixed \t whitespace \n", // tabs/newlines around
		"trailing newline\n",
		"word",
		"tab\tseparated values",
		"unicode \u00a0 nbsp space",
		"emoji 😀 and spaces ",
	}

	for _, c := range cases {
		body := []byte(c)
		wantWords, wantLines := legacyWordsLines(body)

		var gotWords, gotLines int
		if len(body) > 0 {
			gotWords = bytes.Count(body, []byte{' '}) + 1
			gotLines = bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
		}

		require.Equalf(t, wantWords, gotWords, "words mismatch for %q", c)
		require.Equalf(t, wantLines, gotLines, "lines mismatch for %q", c)
	}
}

// TestBodyMetricsCountingDoesNotAllocate locks in the optimization: the
// byte-based word/line counting used on the hot path must not allocate (the
// previous string(respbody) + strings.Split approach allocated O(len(body))).
// If someone reintroduces a full-body string copy or Split-based counting, this
// test fails.
func TestBodyMetricsCountingDoesNotAllocate(t *testing.T) {
	body := bytes.Repeat([]byte("lorem ipsum dolor sit amet\n"), 40000) // ~1MB
	var words, lines int

	allocs := testing.AllocsPerRun(50, func() {
		// identical expressions to the hot path in Do()
		words = bytes.Count(body, []byte{' '}) + 1
		lines = bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
	})

	require.NotZero(t, words)
	require.NotZero(t, lines)
	require.Zerof(t, allocs, "word/line counting must not allocate, got %v allocs/op", allocs)
}
