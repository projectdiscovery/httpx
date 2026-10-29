package runner

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/stretchr/testify/require"
)

type headerLog struct {
	mu      sync.Mutex
	headers map[string]http.Header
}

func (l *headerLog) record(path string, h http.Header) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.headers == nil {
		l.headers = make(map[string]http.Header)
	}
	l.headers[path] = h.Clone()
}

func (l *headerLog) get(path string) http.Header {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.headers[path]
}

// TestRedirectCredentialsStayOnHost checks that -fr does not send -H cookies
// or secret-file headers to another host, and keeps them on the same host.
func TestRedirectCredentialsStayOnHost(t *testing.T) {
	log := &headerLog{}

	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record("third"+r.URL.Path, r.Header)
		_, _ = io.WriteString(w, "third")
	}))
	defer third.Close()
	thirdURL := strings.Replace(third.URL, "127.0.0.1", "localhost", 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/away", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, thirdURL+"/landing", http.StatusFound)
	})
	mux.HandleFunc("/stay", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		log.record("target/final", r.Header)
		_, _ = io.WriteString(w, "final")
	})
	target := httptest.NewServer(mux)
	defer target.Close()

	targetHost := strings.TrimPrefix(target.URL, "http://")
	secrets := filepath.Join(t.TempDir(), "secrets.yaml")
	require.NoError(t, os.WriteFile(secrets, []byte(fmt.Sprintf(`id: test
info:
  name: test
static:
  - type: Header
    domains:
      - %s
    headers:
      - key: X-Api-Key
        value: SECRET-SF-KEY
  - type: Cookie
    domains:
      - %s
    cookies:
      - key: sfsess
        value: SECRET-SF-COOKIE
`, targetHost, targetHost)), 0o600))

	var mu sync.Mutex
	var results []Result
	options := &Options{
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice{target.URL + "/away", target.URL + "/stay"},
		FollowRedirects: true,
		MaxRedirects:    10,
		SecretFile:      secrets,
		CustomHeaders:   customheader.CustomHeaders{"Cookie: sess=SECRET-H-COOKIE"},
		Threads:         1,
		Timeout:         5,
		OnResult: func(r Result) {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
	}
	require.NoError(t, options.ValidateOptions())
	r, err := New(options)
	require.NoError(t, err)
	r.RunEnumeration()
	r.Close()

	for _, res := range results {
		require.NoError(t, res.Err, res.Input)
	}

	got := log.get("third/landing")
	require.NotNil(t, got, "redirect to the other host was not followed")
	require.Empty(t, got.Get("Cookie"), "-H cookie sent to another host")
	require.Empty(t, got.Get("X-Api-Key"), "secret-file header sent to a host it is not scoped to")

	got = log.get("target/final")
	require.NotNil(t, got, "same-host redirect was not followed")
	require.Equal(t, "SECRET-SF-KEY", got.Get("X-Api-Key"))
	cookies := (&http.Request{Header: got}).Cookies()
	counts := map[string]int{}
	for _, c := range cookies {
		counts[c.Name]++
	}
	require.Equal(t, 1, counts["sess"], "-H cookie on a same-host redirect: %v", got.Values("Cookie"))
	require.Equal(t, 1, counts["sfsess"], "secret-file cookie on a same-host redirect: %v", got.Values("Cookie"))
}
