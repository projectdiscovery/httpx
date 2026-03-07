package runner

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
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
	// TODO: Remove the Chrome PID kill code in favor of using Leakless(true).
	// This change will be made if there are no complaints about zombie Chrome processes.
	// Reference: https://github.com/projectdiscovery/httpx/pull/1426
	// pids    map[int32]struct{}
}

func NewBrowser(proxy string, useLocal bool, optionalArgs map[string]string) (*Browser, error) {
	dataStore, err := os.MkdirTemp("", "nuclei-*")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary directory")
	}

	// pids := processutil.FindProcesses(processutil.IsChromeProcess)

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
		Delete("use-mock-keychain").
		Headless(true).
		UserDataDir(dataStore)

	if MustDisableSandbox() {
		chromeLauncher = chromeLauncher.NoSandbox(true)
	}

	executablePath, err := os.Executable()
	if err != nil {
		return nil, err
	}

	// if musl is used, most likely we are on alpine linux which is not supported by go-rod, so we fallback to default chrome
	useMusl, _ := fileutil.UseMusl(executablePath)
	if useLocal || useMusl {
		if chromePath, hasChrome := launcher.LookPath(); hasChrome {
			chromeLauncher.Bin(chromePath)
		} else {
			return nil, errors.New("the chrome browser is not installed")
		}
	}

	if proxy != "" {
		chromeLauncher = chromeLauncher.Proxy(proxy)
	}

	for k, v := range optionalArgs {
		chromeLauncher.Set(flags.Flag(k), v)
	}

	launcherURL, err := chromeLauncher.Launch()
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
		// pids:    pids,
	}
	return engine, nil
}

func (b *Browser) ScreenshotWithBody(url string, timeout time.Duration, idle time.Duration, headers []string, fullPage bool, jsCodes []string) ([]byte, string, []NetworkRequest, error) {
	page, networkRequests, err := b.setupPageAndNavigate(url, timeout, headers, jsCodes)
	if err != nil {
		return nil, "", []NetworkRequest{}, err
	}
	defer b.closePage(page)

	screenshot, body, err := b.takeScreenshotAndGetBody(page, idle, fullPage)
	if err != nil {
		return nil, "", networkRequests, err
	}

	return screenshot, body, networkRequests, nil
}

// setupPageAndNavigate opens a page, performs all adaptive actions including JS injection
func (b *Browser) setupPageAndNavigate(url string, timeout time.Duration, headers []string, jsCodes []string) (*rod.Page, []NetworkRequest, error) {
	page, err := b.engine.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, []NetworkRequest{}, err
	}

	// Enable network
	page.EnableDomain(proto.NetworkEnable{})

	networkRequests := sliceutil.NewSyncSlice[NetworkRequest]()
	requestsMap := mapsutil.NewSyncLockMap[string, *NetworkRequest]()

	// Intercept outbound requests
	go page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
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
	})()
	// Intercept inbound responses
	go page.EachEvent(func(e *proto.NetworkResponseReceived) {
		if requestsMap.Has(string(e.RequestID)) {
			req, _ := requestsMap.Get(string(e.RequestID))
			req.StatusCode = e.Response.Status
		}
	})()
	// Intercept network end requests
	go page.EachEvent(func(e *proto.NetworkLoadingFinished) {
		if requestsMap.Has(string(e.RequestID)) {
			req, _ := requestsMap.Get(string(e.RequestID))
			if req.StatusCode > 0 {
				req.ErrorType = ""
			}
			networkRequests.Append(*req)
		}
	})()
	// Intercept failed request
	go page.EachEvent(func(e *proto.NetworkLoadingFailed) {
		if requestsMap.Has(string(e.RequestID)) {
			req, _ := requestsMap.Get(string(e.RequestID))
			req.StatusCode = 0 // mark to zero
			req.ErrorType = getSimpleErrorType(e.ErrorText, string(e.Type), string(e.BlockedReason))
			if stringsutil.HasPrefixAnyI(req.URL, "http://", "https://") {
				networkRequests.Append(*req)
			}
		}
	})()

	// Handle any popup dialogs
	go page.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		_ = proto.PageHandleJavaScriptDialog{
			Accept:     true,
			PromptText: "",
		}.Call(page)
	})()

	for _, header := range headers {
		headerParts := strings.SplitN(header, ":", 2)
		if len(headerParts) != 2 {
			continue
		}
		key := strings.TrimSpace(headerParts[0])
		value := strings.TrimSpace(headerParts[1])
		_, _ = page.SetExtraHeaders([]string{key, value})
	}

	page = page.Timeout(timeout)

	if err := page.Navigate(url); err != nil {
		return page, networkRequests.Slice, err
	}

	if len(jsCodes) > 0 {
		_, err := b.ExecuteJavascriptCodesWithPage(page, jsCodes)
		if err != nil {
			return page, networkRequests.Slice, err
		}
	}

	page.Timeout(5 * time.Second).WaitNavigation(proto.PageLifecycleEventNameFirstMeaningfulPaint)()

	return page, networkRequests.Slice, nil
}

// takeScreenshotAndGetBody performs the screenshot actions
func (b *Browser) takeScreenshotAndGetBody(page *rod.Page, idle time.Duration, fullPage bool) ([]byte, string, error) {
	if err := page.WaitLoad(); err != nil {
		return nil, "", err
	}
	_ = page.WaitIdle(idle)

	screenshot, err := page.Screenshot(fullPage, &proto.PageCaptureScreenshot{})
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
	// processutil.CloseProcesses(processutil.IsChromeProcess, b.pids)
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
