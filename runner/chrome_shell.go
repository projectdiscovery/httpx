package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/ysmood/leakless"
)

const (
	// chromeShellVersion pins Chrome for Testing's chrome-headless-shell build.
	// Smaller and faster than full Chromium for headless screenshots on Linux.
	chromeShellVersion = "152.0.7977.42"
	// chromeShellRevision is a synthetic cache key for launcher.Browser.Dir.
	chromeShellRevision = 1520797742
)

// HostChromeShell returns the Chrome for Testing chrome-headless-shell zip for
// linux/amd64. Other platforms should not use this host.
func HostChromeShell(_ int) string {
	return fmt.Sprintf(
		"https://storage.googleapis.com/chrome-for-testing-public/%s/linux64/chrome-headless-shell-linux64.zip",
		chromeShellVersion,
	)
}

func supportsChromeShellDownload() bool {
	return runtime.GOOS == "linux" && runtime.GOARCH == "amd64"
}

// ensureLinuxChromeShell downloads chrome-headless-shell once into the rod
// browser cache and returns the executable path.
func ensureLinuxChromeShell() (string, error) {
	b := launcher.NewBrowser()
	b.Revision = chromeShellRevision
	b.Hosts = []launcher.Host{HostChromeShell}

	defer leakless.LockPort(b.LockPort)()

	if p := chromeShellBin(b.Dir()); p != "" {
		return p, nil
	}

	_ = os.RemoveAll(b.Dir())
	if err := b.Download(); err != nil {
		return "", err
	}

	p := chromeShellBin(b.Dir())
	if p == "" {
		return "", fmt.Errorf("chrome-headless-shell binary missing after download in %s", b.Dir())
	}

	// go-rod's linux BinPath expects "chrome"; keep a symlink for Validate().
	chrome := b.BinPath()
	if p != chrome {
		_ = os.Remove(chrome)
		if err := os.Symlink(filepath.Base(p), chrome); err != nil {
			// Non-fatal: we still launch via the real shell path.
			_ = err
		}
	}

	return p, nil
}

func chromeShellBin(dir string) string {
	for _, name := range []string{"chrome-headless-shell", "headless_shell", "chrome"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}
