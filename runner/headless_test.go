package runner

import (
	"testing"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/stretchr/testify/require"
)

func TestDefaultBrowserLauncherKeepsFlagsWithoutBin(t *testing.T) {
	configured := launcher.New().
		Bin("/cache/chrome-headless-shell").
		Set("disable-sync", "true").
		Delete("disable-ipc-flooding-protection").
		Proxy("http://127.0.0.1:8080")

	fallback := defaultBrowserLauncher(configured)

	require.False(t, fallback.Has(flags.Bin))
	require.Equal(t, "true", fallback.Get("disable-sync"))
	require.Equal(t, "http://127.0.0.1:8080", fallback.Get(flags.ProxyServer))
	require.False(t, fallback.Has("disable-ipc-flooding-protection"))
	require.Equal(t, "/cache/chrome-headless-shell", configured.Get(flags.Bin))
}
