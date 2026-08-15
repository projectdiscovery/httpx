package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostChromeShell(t *testing.T) {
	u := HostChromeShell(0)
	if !strings.Contains(u, "chrome-for-testing-public/"+chromeShellVersion+"/") {
		t.Fatalf("unexpected host url: %s", u)
	}
	if !strings.HasSuffix(u, "/linux64/chrome-headless-shell-linux64.zip") {
		t.Fatalf("unexpected zip path: %s", u)
	}
}

func TestChromeShellBin(t *testing.T) {
	dir := t.TempDir()
	if got := chromeShellBin(dir); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}

	shell := filepath.Join(dir, "chrome-headless-shell")
	if err := os.WriteFile(shell, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := chromeShellBin(dir); got != shell {
		t.Fatalf("got %q want %q", got, shell)
	}
}
