package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/common/stringz"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

// testFaviconGIF is a 1x1 GIF, which is enough for content type sniffing.
var testFaviconGIF = []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff" +
	"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

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

// A Host header set with -H selects the virtual host the target serves: the
// favicon must be fetched with that same Host, or the server returns the
// default host's icon (or none at all).
func TestFaviconKeepsCustomHostHeader(t *testing.T) {
	const vhost = "vhost.test"

	var (
		mu        sync.Mutex
		iconHosts []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>vhost</title></head><body>vhost</body></html>`))
		case "/favicon.ico":
			mu.Lock()
			iconHosts = append(iconHosts, req.Host)
			mu.Unlock()
			if req.Host != vhost {
				http.NotFound(w, req)
				return
			}
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(testFaviconGIF)
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()

	var results []Result
	options := &Options{
		Threads:   1,
		RateLimit: 10,
		Retries:   0,
		Timeout:   5,
		Methods:   http.MethodGet,
		Delay:     -1,
		Favicon:   true,
		// The CLI sets these; with 0 no body is read and no icon is found.
		MaxResponseBodySizeToRead: 1 << 20,
		MaxResponseBodySizeToSave: 1 << 20,
		CustomHeaders:             customheader.CustomHeaders{"Host: " + vhost},
		OnResult:                  func(result Result) { results = append(results, result) },
		InputTargetHost:           []string{srv.URL},
	}
	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	hosts := append([]string(nil), iconHosts...)
	mu.Unlock()
	require.NotEmpty(t, hosts, "the favicon was never requested")
	for _, host := range hosts {
		require.Equal(t, vhost, host, "favicon request used the wrong Host header")
	}

	wantMMH3, wantMD5, err := stringz.FaviconHash(testFaviconGIF)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, fmt.Sprintf("%d", wantMMH3), results[0].FavIconMMH3)
	require.Equal(t, wantMD5, results[0].FavIconMD5)
}

func TestFaviconRequestHost(t *testing.T) {
	for _, tc := range []struct {
		name            string
		explicitHost    string
		requestHostname string
		resolvedURL     string
		want            string
	}{
		{
			name:            "virtual host on the target",
			explicitHost:    "vhost.test",
			requestHostname: "127.0.0.1",
			resolvedURL:     "http://127.0.0.1:8080/favicon.ico",
			want:            "vhost.test",
		},
		{
			name:            "virtual host and icon on its own name",
			explicitHost:    "vhost.test",
			requestHostname: "127.0.0.1",
			resolvedURL:     "http://vhost.test/favicon.ico",
			want:            "vhost.test",
		},
		{
			name:            "virtual host and redirect target",
			explicitHost:    "hackerone.com",
			requestHostname: "hackerone.com",
			resolvedURL:     "https://www.hackerone.com/favicon.ico",
			want:            "www.hackerone.com",
		},
		{
			name:            "no virtual host and icon on a CDN",
			requestHostname: "example.com",
			resolvedURL:     "https://cdn.example.net/icon.png",
			want:            "cdn.example.net",
		},
		{
			name:            "no virtual host and icon on the target",
			requestHostname: "127.0.0.1",
			resolvedURL:     "http://127.0.0.1:8080/favicon.ico",
			want:            "127.0.0.1:8080",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolvedURL, err := urlutil.Parse(tc.resolvedURL)
			require.NoError(t, err)
			require.Equal(t, tc.want, faviconRequestHost(tc.explicitHost, tc.requestHostname, resolvedURL))
		})
	}
}
