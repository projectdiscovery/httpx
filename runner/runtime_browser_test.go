package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/stretchr/testify/require"
)

// The page exposes jQuery only at runtime. The name is assembled in script, so
// passive header and body fingerprinting cannot see it.
const runtimeOnlyPage = `<html><head><title>runtime probe</title></head><body>
<p>hello</p>
<script>var a = 'jQ' + 'uery'; window[a] = { fn: { jquery: '3.7.1' } };</script>
</body></html>`

func TestRuntimeFingerprintingWithBrowser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, runtimeOnlyPage)
	}))
	defer srv.Close()

	browser, err := NewBrowser("", true, nil)
	if err != nil {
		t.Skipf("no local chrome available: %v", err)
	}
	defer browser.Close()

	wp, err := wappalyzer.New()
	require.NoError(t, err)

	page, cleanup, err := browser.NavigateForRuntime(srv.URL, 20*time.Second, time.Second, nil)
	require.NoError(t, err)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	passive := wp.FingerprintWithInfo(map[string][]string{"Content-Type": {"text/html"}}, []byte(runtimeOnlyPage))
	require.NotContains(t, passive, "jQuery", "page must not be detectable without runtime evidence")

	matches, err := wp.FingerprintWithRuntime(ctx, map[string][]string{"Content-Type": {"text/html"}}, []byte(runtimeOnlyPage), wappalyzer.RuntimeOptions{
		Collector: newRuntimeCollector(page),
		Timeout:   20 * time.Second,
	})
	require.NoError(t, err)
	require.Contains(t, matches, "jQuery:3.7.1")
}

func TestNavigateForRuntimeCleanupIsSafe(t *testing.T) {
	browser, err := NewBrowser("", true, nil)
	if err != nil {
		t.Skipf("no local chrome available: %v", err)
	}
	defer browser.Close()

	// The target refuses connections. Depending on the browser, navigation either
	// fails or loads an error page, so the test accepts both. Cleanup must be
	// callable on either path.
	page, cleanup, err := browser.NavigateForRuntime("http://127.0.0.1:1/", 3*time.Second, time.Second, nil)
	require.NotNil(t, cleanup)
	if err != nil {
		require.Nil(t, page)
	} else {
		require.NotNil(t, page)
	}
	require.NotPanics(t, cleanup)
	require.NotPanics(t, cleanup)
}
