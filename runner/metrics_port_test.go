package runner

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/projectdiscovery/clistats"
	"github.com/stretchr/testify/require"
)

func TestOptions_ValidateMetricsPort(t *testing.T) {
	tests := []struct {
		port    int
		wantErr bool
	}{
		{port: -1, wantErr: true},
		{port: 0},
		{port: 8080},
		{port: 65535},
		{port: 65536, wantErr: true},
	}

	for _, test := range tests {
		t.Run(fmt.Sprint(test.port), func(t *testing.T) {
			options := &Options{MetricsPort: test.port}
			err := options.ValidateOptions()
			if test.wantErr {
				require.ErrorContains(t, err, "invalid metrics port")
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestOptions_metricsPort(t *testing.T) {
	// a library caller that leaves the field unset gets the clistats default
	require.Equal(t, clistats.DefaultOptions.ListenPort, (&Options{}).metricsPort())
	require.Equal(t, 8080, (&Options{MetricsPort: 8080}).metricsPort())
}

func TestRunner_metricsPort(t *testing.T) {
	defaultPort := clistats.DefaultOptions.ListenPort

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	freePort := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = busy.Close() }()
	busyPort := busy.Addr().(*net.TCPAddr).Port

	tests := []struct {
		name     string
		port     int
		wantSame bool
	}{
		{name: "requested port is used", port: freePort, wantSame: true},
		{name: "busy port falls back to a free one", port: busyPort, wantSame: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := New(&Options{ShowStatistics: true, MetricsPort: test.port})
			require.NoError(t, err)
			defer r.Close()

			stats, ok := r.stats.(*clistats.Statistics)
			require.True(t, ok, "stats should use clistats")
			require.NoError(t, stats.Start())
			defer func() { _ = stats.Stop() }()

			if test.wantSame {
				require.Equal(t, test.port, stats.Options.ListenPort)
			} else {
				require.NotEqual(t, test.port, stats.Options.ListenPort)
			}

			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", stats.Options.ListenPort))
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			// the runner works on a copy of the clistats defaults
			require.Equal(t, defaultPort, clistats.DefaultOptions.ListenPort)
		})
	}
}
