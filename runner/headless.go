package runner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	osutils "github.com/projectdiscovery/utils/os"
)

type NetworkRequest struct {
	RequestID      string
	URL            string
	Method         string
	StatusCode     int
	NetworkRequest string
	ErrorType      string
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

func (b *Browser) ScreenshotWithBody(url string, timeout time.Duration, idle time.Duration, headers []string, fullPage bool) ([]byte, string, []NetworkRequest, error) {
	page, err := b.engine.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, "", []NetworkRequest{}, err
	}

	// Enable network
	page.EnableDomain(proto.NetworkEnable{})

	var networkRequests []NetworkRequest
	var networkMutex sync.Mutex
	requestsMap := make(map[string]*NetworkRequest)

	// Intercept out request
	go page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if !strings.HasPrefix(e.Request.URL, "http://") && !strings.HasPrefix(e.Request.URL, "https://") {
			return
		}
		networkMutex.Lock()
		defer networkMutex.Unlock()
		req := &NetworkRequest{
			RequestID:  string(e.RequestID),
			URL:        e.Request.URL,
			Method:     e.Request.Method,
			StatusCode: -1,
			ErrorType:  "QUIT_BEFORE_RESSOURCE_LOADING_END",
		}
		requestsMap[string(e.RequestID)] = req
	})()
	// Intercept response
	go page.EachEvent(func(e *proto.NetworkResponseReceived) {
		networkMutex.Lock()
		defer networkMutex.Unlock()
		if req, exists := requestsMap[string(e.RequestID)]; exists {
			req.StatusCode = e.Response.Status
		}
	})()
	//  Intercept end request
	go page.EachEvent(func(e *proto.NetworkLoadingFinished) {
		networkMutex.Lock()
		defer networkMutex.Unlock()
		if req, exists := requestsMap[string(e.RequestID)]; exists {
			if req.StatusCode > 0 {
				req.ErrorType = ""
			}
			networkRequests = append(networkRequests, *req)
		}
	})()
	//Intercept failed request
	go page.EachEvent(func(e *proto.NetworkLoadingFailed) {
		networkMutex.Lock()
		defer networkMutex.Unlock()
		if req, exists := requestsMap[string(e.RequestID)]; exists {
			req.StatusCode = 0 // Marquer comme échec
			req.ErrorType = getSimpleErrorType(e.ErrorText, string(e.Type), string(e.BlockedReason))
			if strings.HasPrefix(req.URL, "http://") || strings.HasPrefix(req.URL, "https://") {
				networkRequests = append(networkRequests, *req)
			}
		}
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
	defer page.Close()

	if err := page.Navigate(url); err != nil {
		return nil, "", networkRequests, err
	}

	page.Timeout(5 * time.Second).WaitNavigation(proto.PageLifecycleEventNameFirstMeaningfulPaint)()

	if err := page.WaitLoad(); err != nil {
		return nil, "", networkRequests, err
	}
	_ = page.WaitIdle(idle)

	screenshot, err := page.Screenshot(fullPage, &proto.PageCaptureScreenshot{})
	if err != nil {
		return nil, "", networkRequests, err
	}

	body, err := page.HTML()
	if err != nil {
		return screenshot, "", networkRequests, err
	}

	return screenshot, body, networkRequests, nil
}

func (b *Browser) Close() {
	b.engine.Close()
	os.RemoveAll(b.tempDir)
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
