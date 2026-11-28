//go:build darwin || linux

package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunnerOutputWriteFailure(t *testing.T) {
	if os.Getenv("HTTPX_OUTPUT_WRITE_CHILD") == "1" {
		options := &Options{
			InputTargetHost:  []string{os.Getenv("HTTPX_OUTPUT_WRITE_TARGET")},
			Output:           os.Getenv("HTTPX_OUTPUT_WRITE_PATH"),
			JSONOutput:       true,
			Methods:          http.MethodGet,
			Threads:          1,
			RateLimit:        10,
			Timeout:          2,
			Delay:            -1,
			NoFallbackScheme: true,
			Stream:           true,
			SkipDedupe:       true,
			DisableStdout:    true,
			OnResult: func(Result) {
				signal.Ignore(syscall.SIGXFSZ)
				if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
					panic(err)
				}
			},
		}
		require.NoError(t, options.ValidateOptions())
		r, err := New(options)
		require.NoError(t, err)
		defer r.Close()
		r.RunEnumeration()
		return
	}

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	outputPath := filepath.Join(t.TempDir(), "output.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunnerOutputWriteFailure$")
	cmd.Env = append(os.Environ(),
		"HTTPX_OUTPUT_WRITE_CHILD=1",
		"HTTPX_OUTPUT_WRITE_TARGET="+server.URL,
		"HTTPX_OUTPUT_WRITE_PATH="+outputPath,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "child scan did not finish: %s", output)
	require.EqualValues(t, 1, requests.Load(), "local target was not probed: %s", output)
	require.Error(t, err, "scan exited successfully after losing output: %s", output)
	require.Contains(t, string(output), "Could not write output file")
	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	require.Zero(t, info.Size())
}
