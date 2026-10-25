package runner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// An absolute favicon href that can't be fetched must not be retried as a
// path on the target ("/http://...").
func TestFaviconAbsoluteHrefIsNotRetriedAsRootPath(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		paths = append(paths, req.URL.Path)
		mu.Unlock()
		_, _ = w.Write([]byte(`<html><head><link rel="icon" href="http://127.0.0.1:1/icon.png"></head></html>`))
	}))
	defer srv.Close()

	options := &Options{
		Threads:   1,
		RateLimit: 10,
		Retries:   0,
		Timeout:   5,
		Methods:   http.MethodGet,
		Delay:     -1,
		Favicon:   true,
		// The CLI sets these; with 0 no body is read and no <link> is seen.
		MaxResponseBodySizeToRead: 1 << 20,
		MaxResponseBodySizeToSave: 1 << 20,
		OnResult:                  func(Result) {},
		InputTargetHost:           []string{srv.URL},
	}
	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, paths)
	for _, p := range paths {
		require.False(t, strings.HasPrefix(p, "/http"), "unexpected request to %q", p)
	}
}
