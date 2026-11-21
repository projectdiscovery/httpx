package runner

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// In colored output, -sc printed nothing for a 500 and judged chain entries by
// the final status code, so a 302 -> 500 chain came out as [302,].
func TestStatusCodeIsPrintedInColor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/error", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	var (
		mu      sync.Mutex
		results []Result
	)
	options := &Options{
		Threads:         1,
		RateLimit:       10,
		Retries:         0,
		Timeout:         5,
		Methods:         http.MethodGet,
		Delay:           -1,
		StatusCode:      true,
		FollowRedirects: true,
		MaxRedirects:    10,
		OnResult: func(r Result) {
			if r.Err != nil || r.URL == "" {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
		InputTargetHost: []string{srv.URL + "/error", srv.URL + "/redirect"},
	}

	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, results, 2)
	ansiEscape := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	for _, result := range results {
		got := ansiEscape.ReplaceAllString(result.str, "")
		if strings.HasSuffix(result.URL, "/redirect") {
			require.Contains(t, got, "[302,500]")
		} else {
			require.Contains(t, got, "[500]")
		}
	}
}
