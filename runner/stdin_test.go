package runner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// openStdin replaces os.Stdin with a pipe and returns its writer. The pipe
// stays open until the writer is closed, as under ssh without a tty or a
// subprocess that inherits its parent's stdin.
func openStdin(t *testing.T) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	stdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = stdin
		_ = writer.Close()
		_ = reader.Close()
	})
	return writer
}

func finishes(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on an open stdin")
	}
}

func drain(out chan string) (items []string) {
	for item := range out {
		items = append(items, item)
	}
	return items
}

func TestRunner_skipsOpenStdin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "targets.txt")
	require.NoError(t, os.WriteFile(file, []byte("b.example\n"), 0o600))

	cases := map[string]Options{
		"-u":                {InputTargetHost: []string{"a.example"}},
		"-l":                {InputFile: file},
		"-stream -u":        {Stream: true, InputTargetHost: []string{"a.example"}},
		"-stream -l":        {Stream: true, InputFile: file},
		"-stream -no-stdin": {Stream: true, DisableStdin: true},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			openStdin(t)
			r, err := New(&options)
			require.NoError(t, err)
			defer r.Close()

			finishes(t, func() {
				if options.Stream {
					out, err := r.streamInput()
					require.NoError(t, err)
					drain(out)
					return
				}
				r.prepareInput()
			})
		})
	}
}

func TestRunner_readsStdinWithoutOtherTargets(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "-stream"}[stream], func(t *testing.T) {
			stdin := openStdin(t)
			_, err := stdin.WriteString("a.example\n")
			require.NoError(t, err)
			require.NoError(t, stdin.Close())

			r, err := New(&Options{Stream: stream})
			require.NoError(t, err)
			defer r.Close()

			if stream {
				out, err := r.streamInput()
				require.NoError(t, err)
				require.Equal(t, []string{"a.example"}, drain(out))
				return
			}
			r.prepareInput()
			_, ok := r.hm.Get("a.example")
			require.True(t, ok)
		})
	}
}
