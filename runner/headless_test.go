package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/stretchr/testify/require"
)

type requestLog struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (l *requestLog) handler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.reqs = append(l.reqs, r.Clone(r.Context()))
		l.mu.Unlock()
		next(w, r)
	}
}

func (l *requestLog) all() []*http.Request {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*http.Request{}, l.reqs...)
}

func serverPort(t *testing.T, s *httptest.Server) int {
	u, err := url.Parse(s.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	return port
}

func TestBrowserAllowRequest(t *testing.T) {
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	require.NoError(t, err)
	defer dialer.Close()

	np, err := networkpolicy.New(networkpolicy.Options{
		DenyList:     []string{"127.0.0.0/8"},
		DenyPortList: []int{9202},
	})
	require.NoError(t, err)

	b := &Browser{}
	b.SetNetworkPolicy(np, dialer)

	mustParse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		return u
	}
	require.False(t, b.allowRequest(mustParse("http://127.0.0.1/")), "denied address")
	require.False(t, b.allowRequest(mustParse("http://localhost:8080/")), "host name resolving to a denied address")
	require.False(t, b.allowRequest(mustParse("http://93.184.215.14:9202/")), "denied port")
	require.False(t, b.allowRequest(mustParse("file:///etc/passwd")), "non-http scheme")
	require.True(t, b.allowRequest(mustParse("https://93.184.215.14/")))

	// with a proxy the proxy resolves names; address rules still apply to IPs
	b.proxy = "http://127.0.0.1:8080"
	require.False(t, b.allowRequest(mustParse("http://127.0.0.1/")))
	require.False(t, b.allowRequest(mustParse("http://example.com:9202/")))
}

// TestScreenshotNetworkPolicyAndHeaders runs Chrome: redirects, iframes and
// sub-resources must obey the network policy, and custom headers must go
// only to the probed origin.
func TestScreenshotNetworkPolicyAndHeaders(t *testing.T) {
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("chrome is not installed")
	}

	denied := &requestLog{}
	internal := httptest.NewServer(denied.handler(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<h1>INTERNAL-ADMIN-PANEL</h1>")
	}))
	defer internal.Close()

	third := &requestLog{}
	thirdParty := httptest.NewServer(third.handler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
	}))
	defer thirdParty.Close()
	// a different origin that the policy allows
	thirdURL := strings.Replace(thirdParty.URL, "127.0.0.1", "localhost", 1)

	targetLog := &requestLog{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", targetLog.handler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<html><body><h1>page</h1><img src="%s/pixel.gif"><iframe src="%s/admin"></iframe><script>fetch(%q).catch(function(){})</script></body></html>`,
			thirdURL, internal.URL, internal.URL+"/fetch")
	}))
	mux.HandleFunc("/redir", targetLog.handler(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/admin", http.StatusFound)
	}))
	target := httptest.NewServer(mux)
	defer target.Close()

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	require.NoError(t, err)
	defer dialer.Close()

	np, err := networkpolicy.New(networkpolicy.Options{DenyPortList: []int{serverPort(t, internal)}})
	require.NoError(t, err)

	browser, err := NewBrowser("", true, nil)
	require.NoError(t, err)
	defer browser.Close()
	browser.SetNetworkPolicy(np, dialer)

	headers := []string{"Authorization: Bearer SECRET-H-TOKEN", "X-Api-Key: SECRET-H-KEY"}

	_, body, _, err := browser.ScreenshotWithBody(target.URL+"/", 10*time.Second, time.Second, headers, false, nil)
	require.NoError(t, err)
	require.Contains(t, body, "page")

	_, body, _, _ = browser.ScreenshotWithBody(target.URL+"/redir", 10*time.Second, time.Second, headers, false, nil)
	require.NotContains(t, body, "INTERNAL-ADMIN-PANEL")

	require.Empty(t, denied.all(), "the browser reached a host the network policy denies")

	thirdReqs := third.all()
	require.NotEmpty(t, thirdReqs, "the allowed third-party image was not loaded")
	for _, r := range thirdReqs {
		require.Empty(t, r.Header.Get("Authorization"), "custom header sent to a third-party origin")
		require.Empty(t, r.Header.Get("X-Api-Key"), "custom header sent to a third-party origin")
	}

	targetReqs := targetLog.all()
	require.NotEmpty(t, targetReqs)
	for _, r := range targetReqs {
		require.Equal(t, "Bearer SECRET-H-TOKEN", r.Header.Get("Authorization"), r.URL.Path)
		require.Equal(t, "SECRET-H-KEY", r.Header.Get("X-Api-Key"), r.URL.Path)
	}
}
