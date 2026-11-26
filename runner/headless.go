package runner

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/rod"
	"github.com/projectdiscovery/rod/lib/launcher"
	"github.com/projectdiscovery/rod/lib/launcher/flags"
	"github.com/projectdiscovery/rod/lib/proto"
	rodutils "github.com/projectdiscovery/rod/lib/utils"
	"github.com/projectdiscovery/utils/chromeshell"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	mapsutil "github.com/projectdiscovery/utils/maps"
	osutils "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

type NetworkRequest struct {
	RequestID  string
	URL        string
	Method     string
	StatusCode int
	ErrorType  string
}

// MustDisableSandbox determines if the current os and user needs sandbox mode disabled
func MustDisableSandbox() bool {
	// linux with root user needs "--no-sandbox" option
	// https://github.com/chromium/chromium/blob/c4d3c31083a2e1481253ff2d24298a1dfe19c754/chrome/test/chromedriver/client/chromedriver.py#L209
	return osutils.IsLinux() && os.Geteuid() == 0
}

type Browser struct {
	tempDir string
	engine  *rod.Browser
	proxy   string
	// policy and dialer restrict every request the browser makes
	policy *networkpolicy.NetworkPolicy
	dialer *fastdialer.Dialer
}

// preferSystemBrowser reports whether screenshots must launch an installed
// browser instead of the Chromium build go-rod downloads.
func preferSystemBrowser(useLocal bool) bool {
	return useLocal || hostUsesMusl()
}

// hostUsesMusl reports whether this machine's own libc is musl.
// Release binaries are built with CGO_ENABLED=0, so the executable has no
// libc to inspect. /bin/sh does: Alpine's shell is musl, and Debian's shell
// stays glibc even when the musl package has installed an ld-musl loader.
// A static shell falls back to the loaders, and a glibc loader wins so that
// side-installed musl does not hide go-rod's browser.
func hostUsesMusl() bool {
	return muslHost("/")
}

func muslHost(root string) bool {
	if musl, err := fileutil.UseMusl(filepath.Join(root, "bin/sh")); err == nil && musl {
		return true
	}
	if pathGlobExists(root, glibcLoaderPatterns) {
		return false
	}
	return pathGlobExists(root, muslLoaderPatterns)
}

var glibcLoaderPatterns = []string{
	"lib/ld-linux*.so*",
	"lib64/ld-linux*.so*",
	"usr/lib/ld-linux*.so*",
	"usr/lib64/ld-linux*.so*",
}

var muslLoaderPatterns = []string{
	"lib/ld-musl-*.so*",
	"lib/libc.musl-*.so*",
	"lib64/ld-musl-*.so*",
	"usr/lib/ld-musl-*.so*",
}

func pathGlobExists(root string, patterns []string) bool {
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err == nil && len(matches) > 0 {
			return true
		}
	}
	return false
}

func NewBrowser(proxy string, useLocal bool, optionalArgs map[string]string) (*Browser, error) {
	return newBrowser(proxy, proxy, useLocal, optionalArgs)
}

// newBrowser is NewBrowser with a separate proxy for the chrome-headless-shell
// download. An empty downloadProxy uses the environment proxy.
func newBrowser(proxy, downloadProxy string, useLocal bool, optionalArgs map[string]string) (*Browser, error) {
	dataStore, err := os.MkdirTemp("", "nuclei-*")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary directory")
	}

	chromeLauncher := launcher.New().
		Leakless(true).
		Set("disable-gpu", "true").
		Set("ignore-certificate-errors", "true").
		Set("ignore-certificate-errors", "1").
		Set("disable-crash-reporter", "true").
		Set("disable-notifications", "true").
		Set("hide-scrollbars", "true").
		Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
		Set("mute-audio", "true").
		Set("incognito", "true").
		// Performance: keep background/occluded tabs running at full speed so
		// many concurrent screenshot pages don't get render-throttled.
		Set("disable-background-timer-throttling", "true").
		Set("disable-backgrounding-occluded-windows", "true").
		Set("disable-renderer-backgrounding", "true").
		Set("disable-hang-monitor", "true").
		// Performance: strip background chrome services we never use.
		Set("disable-background-networking", "true").
		Set("disable-client-side-phishing-detection", "true").
		Set("disable-component-update", "true").
		Set("disable-default-apps", "true").
		Set("disable-domain-reliability", "true").
		Set("disable-extensions", "true").
		Set("disable-sync", "true").
		Set("no-first-run", "true").
		Set("no-default-browser-check", "true").
		Set("metrics-recording-only", "true").
		Set("safebrowsing-disable-auto-update", "true").
		// site-per-process stays enabled: screenshots render untrusted pages, so
		// Chromium's cross-origin renderer isolation is worth the extra processes.
		Set("disable-features", "Translate,BackForwardCache,AcceptCHFrame,MediaRouter,OptimizationHints").
		Delete("use-mock-keychain").
		// rod disables IPC flooding protection by default; keep it on because
		// untrusted pages share one browser process and must not starve each other.
		Delete("disable-ipc-flooding-protection").
		Headless(true).
		UserDataDir(dataStore)

	if MustDisableSandbox() {
		chromeLauncher = chromeLauncher.NoSandbox(true)
	}

	// go-rod downloads a glibc Chromium, which cannot run on a musl host.
	usingChromeShell := false
	if preferSystemBrowser(useLocal) {
		if chromePath, hasChrome := launcher.LookPath(); hasChrome {
			chromeLauncher.Bin(chromePath)
		} else {
			return nil, errors.New("the chrome browser is not installed")
		}
	} else if chromeshell.Supported() {
		// Prefer chrome-headless-shell on linux/amd64: smaller download and
		// faster headless screenshots than full Chromium snapshots.
		if shellPath, err := ensureChromeShell(downloadProxy); err == nil {
			chromeLauncher.Bin(shellPath)
			usingChromeShell = true
		} else {
			gologger.Warning().Msgf("Could not prepare chrome-headless-shell, using the default browser: %s\n", err)
		}
	}

	if proxy == "" {
		for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			if v := os.Getenv(k); v != "" {
				proxy = v
				break
			}
		}
	}
	if proxy != "" {
		chromeLauncher = chromeLauncher.Proxy(proxy)
	}

	for k, v := range optionalArgs {
		chromeLauncher.Set(flags.Flag(k), v)
	}

	launcherURL, err := chromeLauncher.Launch()
	if err != nil && usingChromeShell {
		// A damaged cached shell must not disable screenshots: retry once with
		// the rod default browser and the same flags.
		gologger.Warning().Msgf("Could not launch chrome-headless-shell, using the default browser: %s\n", err)
		chromeLauncher = defaultBrowserLauncher(chromeLauncher)
		launcherURL, err = chromeLauncher.Launch()
	}
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(launcherURL)
	if browserErr := browser.Connect(); browserErr != nil {
		return nil, browserErr
	}

	engine := &Browser{
		tempDir: dataStore,
		engine:  browser,
		proxy:   proxy,
	}
	return engine, nil
}

// SetNetworkPolicy makes the browser check every request, redirects and
// sub-resources included, against np. Host names are resolved with dialer.
func (b *Browser) SetNetworkPolicy(np *networkpolicy.NetworkPolicy, dialer *fastdialer.Dialer) {
	b.policy = np
	b.dialer = dialer
}

func (b *Browser) ScreenshotWithBody(url string, timeout time.Duration, idle time.Duration, headers []string, fullPage bool, jsCodes []string) ([]byte, string, []NetworkRequest, error) {
	page, router, networkRequests, err := b.setupPageAndNavigate(url, timeout, idle, headers, jsCodes)
	if router != nil {
		defer func() { _ = router.Stop() }()
	}
	if err != nil {
		return nil, "", []NetworkRequest{}, err
	}
	defer b.closePage(page)

	screenshot, body, err := b.takeScreenshotAndGetBody(page, fullPage)
	if err != nil {
		return nil, "", networkRequests, err
	}

	return screenshot, body, networkRequests, nil
}

// setupPageAndNavigate opens a page, performs all adaptive actions including JS injection
func (b *Browser) setupPageAndNavigate(url string, timeout time.Duration, idle time.Duration, headers []string, jsCodes []string) (*rod.Page, *rod.HijackRouter, []NetworkRequest, error) {
	page, err := b.engine.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, nil, []NetworkRequest{}, err
	}

	// Enable network
	page.EnableDomain(proto.NetworkEnable{})

	networkRequests := sliceutil.NewSyncSlice[NetworkRequest]()
	requestsMap := mapsutil.NewSyncLockMap[string, *NetworkRequest]()

	// Track requests from outbound to finished or failed. The handlers share
	// the *NetworkRequest values, so they are registered in one EachEvent,
	// which calls them one at a time from a single goroutine.
	go page.EachEvent(
		// Intercept outbound requests
		func(e *proto.NetworkRequestWillBeSent) {
			if !stringsutil.HasPrefixAnyI(e.Request.URL, "http://", "https://") {
				return
			}
			req := &NetworkRequest{
				RequestID:  string(e.RequestID),
				URL:        e.Request.URL,
				Method:     e.Request.Method,
				StatusCode: -1,
				ErrorType:  "QUIT_BEFORE_RESOURCE_LOADING_END",
			}
			_ = requestsMap.Set(string(e.RequestID), req)
		},
		// Intercept inbound responses
		func(e *proto.NetworkResponseReceived) {
			if requestsMap.Has(string(e.RequestID)) {
				req, _ := requestsMap.Get(string(e.RequestID))
				req.StatusCode = e.Response.Status
			}
		},
		// Intercept network end requests
		func(e *proto.NetworkLoadingFinished) {
			if requestsMap.Has(string(e.RequestID)) {
				req, _ := requestsMap.Get(string(e.RequestID))
				if req.StatusCode > 0 {
					req.ErrorType = ""
				}
				networkRequests.Append(*req)
			}
		},
		// Intercept failed request
		func(e *proto.NetworkLoadingFailed) {
			if requestsMap.Has(string(e.RequestID)) {
				req, _ := requestsMap.Get(string(e.RequestID))
				req.StatusCode = 0 // mark to zero
				req.ErrorType = getSimpleErrorType(e.ErrorText, string(e.Type), string(e.BlockedReason))
				if stringsutil.HasPrefixAnyI(req.URL, "http://", "https://") {
					networkRequests.Append(*req)
				}
			}
		},
	)()

	// Handle any popup dialogs
	go page.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		_ = proto.PageHandleJavaScriptDialog{
			Accept:     true,
			PromptText: "",
		}.Call(page)
	})()

	// Every request goes through the hijack router: it applies the network
	// policy and adds the custom headers only to the probed origin.
	// Page-wide SetExtraHeaders would send them to every origin.
	router, err := b.hijackRequests(page, url, parseHeaders(headers))
	if err != nil {
		return page, nil, snapshot(networkRequests), err
	}

	page = page.Timeout(timeout)
	// The readiness waits stop early enough to leave time for the capture,
	// so a request that never ends delays the screenshot but does not fail it.
	readyCtx, cancelReady := context.WithTimeout(page.GetContext(), timeout-timeout/4)
	defer cancelReady()
	var waitReqIdle func(context.Context)
	if idle > 0 {
		// Register before Navigate so the first SPA XHRs are tracked by the
		// request-idle waiter. Zero/negative idle skips this (the idle waiter
		// and WaitDOMStable reject non-positive durations).
		waitReqIdle = waitRequestIdle(page, idle)
	}

	if err := page.Navigate(url); err != nil {
		return page, router, snapshot(networkRequests), err
	}

	if len(jsCodes) > 0 {
		_, err := b.ExecuteJavascriptCodesWithPage(page, jsCodes)
		if err != nil {
			return page, router, snapshot(networkRequests), err
		}
	}

	b.waitPageReady(page.Context(readyCtx), idle, waitReqIdle)

	return page, router, snapshot(networkRequests), nil
}

// hijackRequests intercepts the page requests. WebSocket connections are not
// visible to the Fetch domain, so they are blocked when a policy is set.
func (b *Browser) hijackRequests(page *rod.Page, targetURL string, headers map[string]string) (*rod.HijackRouter, error) {
	if b.policy == nil && len(headers) == 0 {
		return nil, nil
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	if b.policy != nil {
		if err := (proto.NetworkSetBlockedURLs{Urls: []string{"ws://*", "wss://*"}}).Call(page); err != nil {
			return nil, err
		}
	}
	router := page.HijackRequests()
	if err := router.Add("*", "", func(h *rod.Hijack) {
		reqURL := h.Request.URL()
		if !b.allowRequest(reqURL) {
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		continueRequest := &proto.FetchContinueRequest{}
		if len(headers) > 0 && sameOrigin(target, reqURL) {
			continueRequest.Headers = mergeRequestHeaders(h.Request.Headers(), headers)
		}
		h.ContinueRequest(continueRequest)
	}); err != nil {
		return nil, err
	}
	go router.Run()
	return router, nil
}

// allowRequest reports whether the browser may send a request to u. Only
// http and https are allowed. With a network policy, the host, the port and
// every resolved address must pass it, as for the http client.
func (b *Browser) allowRequest(u *url.URL) bool {
	if u == nil || !stringsutil.EqualFoldAny(u.Scheme, "http", "https") {
		return false
	}
	if b.policy == nil {
		return true
	}
	hostname := u.Hostname()
	port, err := strconv.Atoi(effectivePort(u))
	if err != nil || !b.policy.Validate(hostname) || !b.policy.ValidatePort(port) {
		return false
	}
	if iputil.IsIP(hostname) {
		return true
	}
	// Chrome maps localhost names to loopback itself and connects to them
	// directly, also with a proxy, so check the loopback addresses.
	if isLocalhostName(hostname) {
		return b.policy.ValidateAddress("127.0.0.1") && b.policy.ValidateAddress("::1")
	}
	// with a proxy, the proxy resolves the name and the http client does
	// not check the target address either. Chrome on Windows sends
	// "loopback" directly, so that name is still resolved here.
	if b.proxy != "" && !isLoopbackBypassName(hostname) {
		return true
	}
	if b.dialer == nil {
		return false
	}
	dnsData, err := b.dialer.GetDNSData(hostname)
	if err != nil || dnsData == nil || len(dnsData.A)+len(dnsData.AAAA) == 0 {
		return false
	}
	for _, ip := range append(append([]string{}, dnsData.A...), dnsData.AAAA...) {
		if !b.policy.ValidateAddress(ip) {
			return false
		}
	}
	return true
}

// parseHeaders turns "Name: value" items into a map.
func parseHeaders(headers []string) map[string]string {
	parsed := make(map[string]string, len(headers))
	for _, header := range headers {
		headerParts := strings.SplitN(header, ":", 2)
		if len(headerParts) != 2 {
			continue
		}
		parsed[strings.TrimSpace(headerParts[0])] = strings.TrimSpace(headerParts[1])
	}
	return parsed
}

// sameOrigin compares scheme, hostname and effective port.
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

// isLocalhostName reports names that Chrome maps to loopback itself and
// connects to directly, without DNS and without the proxy.
func isLocalhostName(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// isLoopbackBypassName reports "loopback", a name that Chrome on Windows
// resolves normally but connects to without the proxy.
func isLoopbackBypassName(host string) bool {
	return strings.EqualFold(strings.TrimSuffix(host, "."), "loopback")
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// mergeRequestHeaders overlays extra on the request headers. Continuing a
// Fetch request with Headers replaces the whole set.
func mergeRequestHeaders(existing proto.NetworkHeaders, extra map[string]string) []*proto.FetchHeaderEntry {
	out := make([]*proto.FetchHeaderEntry, 0, len(existing)+len(extra))
	seen := make(map[string]struct{}, len(extra))
	for name, value := range extra {
		out = append(out, &proto.FetchHeaderEntry{Name: name, Value: value})
		seen[strings.ToLower(name)] = struct{}{}
	}
	for name, value := range existing {
		if _, ok := seen[strings.ToLower(name)]; ok {
			continue
		}
		out = append(out, &proto.FetchHeaderEntry{Name: name, Value: value.Str()})
	}
	return out
}

// waitPageReady blocks until the page is visually settled so we don't capture a
// half-rendered SPA. It gates on three independent signals, each bounded by the
// page timeout:
//   - window.onload
//   - network request-idle (a quiet network window)
//   - DOM stability (the rendered tree stops mutating)
//
// SPAs paint late: the network can briefly go quiet before hydration starts, so
// request-idle alone can fire on the boot screen. Requiring DOM stability on top
// closes that gap. DOM stability is re-checked after the network settles so the
// first snapshot is taken post-hydration rather than on the boot screen.
func (b *Browser) waitPageReady(page *rod.Page, idle time.Duration, waitReqIdle func(context.Context)) {
	_ = page.WaitLoad()
	if idle <= 0 || waitReqIdle == nil {
		return
	}
	waitReqIdle(page.GetContext())
	_ = page.WaitDOMStable(idle, 0)
}

// idleIgnoredTypes are the request types that do not delay the screenshot,
// the same as the defaults of rod's WaitRequestIdle.
var idleIgnoredTypes = []proto.NetworkResourceType{
	proto.NetworkResourceTypeWebSocket,
	proto.NetworkResourceTypeEventSource,
	proto.NetworkResourceTypeMedia,
	proto.NetworkResourceTypeImage,
	proto.NetworkResourceTypeFont,
}

// waitRequestIdle starts tracking the page requests and returns a function
// that blocks until no tracked request was pending for d, or until its
// context ends. It is rod's WaitRequestIdle without the requests that have
// no loader: Chrome reports the main script request of a dedicated worker
// on the page session with an empty loader id, but reports its end on the
// worker target, which is not attached. rod would wait for that request
// until the page timeout.
func waitRequestIdle(page *rod.Page, d time.Duration) func(context.Context) {
	page, cancel := page.WithCancel()
	pending := map[proto.NetworkRequestID]struct{}{}
	idle := rodutils.NewIdleCounter(d)
	done := func(id proto.NetworkRequestID) {
		if _, ok := pending[id]; ok {
			delete(pending, id)
			idle.Done()
		}
	}
	wait := page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if e.LoaderID == "" || slices.Contains(idleIgnoredTypes, e.Type) {
			return
		}
		// a redirect sends the same request id again
		if _, ok := pending[e.RequestID]; !ok {
			pending[e.RequestID] = struct{}{}
			idle.Add()
		}
	}, func(e *proto.NetworkLoadingFinished) {
		done(e.RequestID)
	}, func(e *proto.NetworkLoadingFailed) {
		done(e.RequestID)
	})
	return func(ctx context.Context) {
		go func() {
			idle.Wait(ctx)
			cancel()
		}()
		wait()
	}
}

// defaultBrowserLauncher returns a new launcher with the flags of configured,
// minus the browser binary, so rod launches its default browser. A launcher can
// only be launched once.
func defaultBrowserLauncher(configured *launcher.Launcher) *launcher.Launcher {
	fallback := launcher.New()
	fallback.Flags = maps.Clone(configured.Flags)
	fallback.Delete(flags.Bin)
	return fallback
}

// ensureChromeShell fetches the browser under a deadline. The context has to
// reach the download itself: racing a plain Ensure against a timer would only
// abandon the wait, leaving the transfer running and the shared download lock
// held, so the next caller would block behind it.
func ensureChromeShell(proxy string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), chromeshell.DefaultDownloadTimeout)
	defer cancel()
	return chromeshell.EnsureWithOptions(ctx, chromeshell.Options{Proxy: proxy})
}

// takeScreenshotAndGetBody performs the screenshot actions
func (b *Browser) takeScreenshotAndGetBody(page *rod.Page, fullPage bool) ([]byte, string, error) {
	_ = page.WaitRepaint()

	screenshot, err := page.Screenshot(fullPage, &proto.PageCaptureScreenshot{
		OptimizeForSpeed: true,
	})
	if err != nil {
		return nil, "", err
	}

	body, err := page.HTML()
	if err != nil {
		return screenshot, "", err
	}

	return screenshot, body, nil
}

// closePage closes the page and performs cleanup
func (b *Browser) closePage(page *rod.Page) {
	_ = page.Close()
}

func (b *Browser) Close() {
	_ = b.engine.Close()
	_ = os.RemoveAll(b.tempDir)
}
func getSimpleErrorType(errorText, errorType, blockedReason string) string {
	switch blockedReason {
	case "csp":
		return "CSP_BLOCKED"
	case "mixed-content":
		return "MIXED_CONTENT"
	case "origin":
		return "CORS_BLOCKED"
	case "subresource-filter":
		return "AD_BLOCKED"
	}
	switch {
	case strings.Contains(errorText, "net::ERR_NAME_NOT_RESOLVED"):
		return "DNS_ERROR"
	case strings.Contains(errorText, "net::ERR_CONNECTION_REFUSED"):
		return "CONNECTION_REFUSED"
	case strings.Contains(errorText, "net::ERR_CONNECTION_TIMED_OUT"):
		return "TIMEOUT"
	case strings.Contains(errorText, "net::ERR_CERT_"):
		return "SSL_ERROR"
	case strings.Contains(errorText, "net::ERR_BLOCKED_BY_CLIENT"):
		return "CLIENT_BLOCKED"
	case strings.Contains(errorText, "net::ERR_EMPTY_RESPONSE"):
		return "EMPTY_RESPONSE"
	}
	switch errorType {
	case "Failed":
		return "NETWORK_FAILED"
	case "Aborted":
		return "ABORTED"
	case "TimedOut":
		return "TIMEOUT"
	case "AccessDenied":
		return "ACCESS_DENIED"
	case "ConnectionClosed":
		return "CONNECTION_CLOSED"
	case "ConnectionReset":
		return "CONNECTION_RESET"
	case "ConnectionRefused":
		return "CONNECTION_REFUSED"
	case "NameNotResolved":
		return "DNS_ERROR"
	case "BlockedByClient":
		return "CLIENT_BLOCKED"
	}
	// Fallback
	if errorText != "" {
		return "OTHER_ERROR"
	}
	return "UNKNOWN"
}

func (b *Browser) ExecuteJavascriptCodesWithPage(page *rod.Page, jsc []string) ([]*proto.RuntimeRemoteObject, error) {
	outputs := make([]*proto.RuntimeRemoteObject, 0, len(jsc))
	for _, js := range jsc {
		if js == "" {
			continue
		}
		output, err := page.Eval(js)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, output)
	}
	return outputs, nil
}

// snapshot copies the requests collected so far. The event handlers keep
// appending while the page loads, so the slice must not be read directly.
func snapshot(requests *sliceutil.SyncSlice[NetworkRequest]) []NetworkRequest {
	out := make([]NetworkRequest, 0, requests.Len())
	requests.Each(func(_ int, req NetworkRequest) error {
		out = append(out, req)
		return nil
	})
	return out
}
