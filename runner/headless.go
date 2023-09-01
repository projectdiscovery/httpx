package runner

import (
	"fmt"
	"os"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	osutils "github.com/projectdiscovery/utils/os"
	processutil "github.com/projectdiscovery/utils/process"
)

// MustDisableSandbox determines if the current os and user needs sandbox mode disabled
func MustDisableSandbox() bool {
	// linux with root user needs "--no-sandbox" option
	// https://github.com/chromium/chromium/blob/c4d3c31083a2e1481253ff2d24298a1dfe19c754/chrome/test/chromedriver/client/chromedriver.py#L209
	return osutils.IsLinux() && os.Geteuid() == 0
}

type Browser struct {
	tempDir string
	engine  *rod.Browser
	pids    map[int32]struct{}
}

func NewBrowser(proxy string, useLocal bool) (*Browser, error) {
	dataStore, err := os.MkdirTemp("", "nuclei-*")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary directory")
	}

	pids := processutil.FindProcesses(processutil.IsChromeProcess)

	chromeLauncher := launcher.New().
		Leakless(false).
		Set("disable-gpu", "true").
		Set("ignore-certificate-errors", "true").
		Set("ignore-certificate-errors", "1").
		Set("disable-crash-reporter", "true").
		Set("disable-notifications", "true").
		Set("hide-scrollbars", "true").
		Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
		Set("mute-audio", "true").
		Set("incognito", "true").
		Set("explicitly-allowed-ports", "1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,77,79,87,95,101,102,103,104,109,110,111,113,115,117,119,123,135,137,139,143,161,179,389,427,465,512,513,514,515,526,530,531,532,540,548,554,556,563,587,601,636,993,995,1719,1720,1723,2049,3659,4045,5060,5061,6000,6566,6665,6666,6667,6668,6669,6697,10080").
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
		pids:    pids,
	}
	return engine, nil
}

func (b *Browser) ScreenshotWithBody(url string, timeout time.Duration) ([]byte, string, error) {
	page, err := b.engine.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, "", err
	}
	page = page.Timeout(timeout)
	defer page.Close()

	if err := page.Navigate(url); err != nil {
		return nil, "", err
	}

	page.Timeout(2 * time.Second).WaitNavigation(proto.PageLifecycleEventNameFirstMeaningfulPaint)()

	if err := page.WaitLoad(); err != nil {
		return nil, "", err
	}
	_ = page.WaitIdle(1 * time.Second)

	screenshot, err := page.Screenshot(true, &proto.PageCaptureScreenshot{})
	if err != nil {
		return nil, "", err
	}

	body, err := page.HTML()
	if err != nil {
		return screenshot, "", err
	}

	return screenshot, body, nil
}

func (b *Browser) Close() {
	b.engine.Close()
	os.RemoveAll(b.tempDir)
	processutil.CloseProcesses(processutil.IsChromeProcess, b.pids)
}
