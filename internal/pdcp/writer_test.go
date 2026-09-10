package pdcp

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/runner"
	"github.com/stretchr/testify/require"
)

func TestAppendResultLine(t *testing.T) {
	t.Run("keeps lines under the limit without flushing", func(t *testing.T) {
		buff := &bytes.Buffer{}
		flushed := 0
		appendResultLine(buff, "ab", 10, func(*bytes.Buffer) error {
			flushed++
			return nil
		})
		appendResultLine(buff, "cd", 10, func(*bytes.Buffer) error {
			flushed++
			return nil
		})
		require.Equal(t, 0, flushed)
		require.Equal(t, "ab\ncd\n", buff.String())
	})

	t.Run("flushes existing data and keeps the overflowing line", func(t *testing.T) {
		buff := &bytes.Buffer{}
		flush := func(b *bytes.Buffer) error {
			require.Equal(t, "aaaa\n", b.String())
			b.Reset()
			return nil
		}
		appendResultLine(buff, "aaaa", 6, flush)
		appendResultLine(buff, "bbbb", 6, flush)
		require.Equal(t, "bbbb\n", buff.String())
	})

	t.Run("does not flush an empty buffer for an oversized line", func(t *testing.T) {
		buff := &bytes.Buffer{}
		flushed := 0
		appendResultLine(buff, "toolong", 4, func(*bytes.Buffer) error {
			flushed++
			return nil
		})
		require.Equal(t, 0, flushed)
		require.Equal(t, "toolong\n", buff.String())
	})

	t.Run("newline counts towards the limit", func(t *testing.T) {
		buff := &bytes.Buffer{}
		const max = 6
		flush := func(b *bytes.Buffer) error {
			b.Reset()
			return nil
		}
		// "abc\n" is 4 bytes, appending "de\n" would reach 7 without counting
		// the newline in the check.
		appendResultLine(buff, "abc", max, flush)
		appendResultLine(buff, "de", max, flush)
		require.LessOrEqual(t, buff.Len(), max)
		require.Equal(t, "de\n", buff.String())
	})

	t.Run("still appends the current line when flush fails", func(t *testing.T) {
		buff := bytes.NewBufferString("old\n")
		appendResultLine(buff, "new", 4, func(*bytes.Buffer) error {
			return errors.New("upload failed")
		})
		require.Equal(t, "old\nnew\n", buff.String())
	})
}

func TestUploadWriterCloseWaits(t *testing.T) {
	u := &UploadWriter{
		done: make(chan struct{}, 1),
		data: make(chan runner.Result, 8),
	}

	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		for range u.data {
		}
		close(started)
		<-release
		u.done <- struct{}{}
		close(u.done)
	}()

	firstDone := make(chan struct{})
	go func() {
		u.Close()
		close(firstDone)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not close the data channel")
	}

	secondDone := make(chan struct{})
	go func() {
		u.Close()
		close(secondDone)
	}()

	select {
	case <-secondDone:
		t.Fatal("second Close returned before autoCommit finished")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-firstDone }()
	go func() { defer wg.Done(); <-secondDone }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close hung")
	}
}
