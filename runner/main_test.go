package runner

import (
	"os"
	"strings"
	"testing"
)

// TestMain keeps pinned.test, the host the tests pin, out of a proxy set in
// the environment, which would resolve it itself, so that they run behind a
// proxy too. Go reads the proxies of the environment once per process, so
// t.Setenv cannot change them for a test.
func TestMain(m *testing.M) {
	noProxy := os.Getenv("NO_PROXY")
	if noProxy == "" {
		noProxy = os.Getenv("no_proxy")
	}
	noProxy = strings.TrimPrefix(noProxy+",pinned.test", ",")
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		_ = os.Setenv(name, noProxy)
	}
	os.Exit(m.Run())
}
