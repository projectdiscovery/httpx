package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const spaHydratedMarker = "hydrated-ok"

// spaHTML is a tiny SPA-style page: it paints a boot screen first, then
// fetches /app.js which hydrates #root after a short delay. Early captures
// only contain "boot"; a correct wait must include spaHydratedMarker.
const spaHTML = `<!doctype html>
<html><head><title>spa-bench</title></head>
<body>
<div id="root">boot</div>
<script>fetch("/app.js").then(function(r){return r.text()}).then(eval);</script>
</body></html>`

const spaJS = `
setTimeout(function(){
  document.getElementById("root").textContent = "` + spaHydratedMarker + `";
}, 80);
`

func startSPAScreenshotServer(t testing.TB) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(spaHTML))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(spaJS))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newScreenshotBrowser(t testing.TB, useLocal bool) *Browser {
	t.Helper()
	browser, err := NewBrowser("", useLocal, nil)
	if err != nil {
		t.Skipf("headless browser unavailable: %v", err)
	}
	t.Cleanup(browser.Close)
	return browser
}

func captureSPA(t testing.TB, browser *Browser, url string) (screenshot []byte, body string) {
	t.Helper()
	screenshot, body, _, err := browser.ScreenshotWithBody(url, 15*time.Second, 200*time.Millisecond, nil, false, nil)
	if err != nil {
		t.Fatalf("screenshot: %v", err)
	}
	return screenshot, body
}

func TestScreenshotSPAWaitsForHydration(t *testing.T) {
	srv := startSPAScreenshotServer(t)
	browser := newScreenshotBrowser(t, false)

	screenshot, body := captureSPA(t, browser, srv.URL)
	if len(screenshot) == 0 {
		t.Fatal("empty screenshot")
	}
	if !strings.Contains(body, spaHydratedMarker) {
		t.Fatalf("early capture: body missing %q\n%s", spaHydratedMarker, body)
	}
}

func TestScreenshotSPAConcurrentNoEarlyCapture(t *testing.T) {
	const workers = 8
	srv := startSPAScreenshotServer(t)
	browser := newScreenshotBrowser(t, false)

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			screenshot, body, _, err := browser.ScreenshotWithBody(srv.URL, 15*time.Second, 200*time.Millisecond, nil, false, nil)
			if err != nil {
				errs <- err
				return
			}
			if len(screenshot) == 0 {
				errs <- fmt.Errorf("empty screenshot")
				return
			}
			if !strings.Contains(body, spaHydratedMarker) {
				errs <- fmt.Errorf("early capture: body missing %q", spaHydratedMarker)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// BenchmarkScreenshotSPA times concurrent captures of the local SPA.
//
// On linux/amd64, /default uses chrome-headless-shell when available and
// /local forces a system Chrome via NewBrowser(..., useLocal=true). Compare:
//
//	go test -bench=BenchmarkScreenshotSPA -benchtime=20s -count=5 ./runner
func BenchmarkScreenshotSPA(b *testing.B) {
	for _, useLocal := range []bool{false, true} {
		name := "default"
		if useLocal {
			name = "local"
		}
		b.Run(name, func(b *testing.B) {
			srv := startSPAScreenshotServer(b)
			browser := newScreenshotBrowser(b, useLocal)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					screenshot, body, _, err := browser.ScreenshotWithBody(srv.URL, 15*time.Second, 200*time.Millisecond, nil, false, nil)
					if err != nil {
						b.Errorf("screenshot: %v", err)
						continue
					}
					if len(screenshot) == 0 || !strings.Contains(body, spaHydratedMarker) {
						b.Errorf("early or empty capture")
					}
				}
			})
		})
	}
}
