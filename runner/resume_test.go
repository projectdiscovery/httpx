package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/goconfig"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/stretchr/testify/require"
)

func TestResumeCfg_AtomicSave(t *testing.T) {
	tempDir := t.TempDir()
	resumePath := filepath.Join(tempDir, "test_resume.cfg")

	cfg := &ResumeCfg{
		Index:      42,
		ResumeFrom: "https://example.com",
	}

	err := cfg.Save(resumePath)
	require.NoError(t, err, "Save should succeed")
	require.True(t, fileutil.FileExists(resumePath), "Resume file should exist")

	var loadedCfg ResumeCfg
	err = goconfig.Load(&loadedCfg, resumePath)
	require.NoError(t, err, "Loading saved config should succeed")
	require.Equal(t, 42, loadedCfg.Index, "Loaded index should match")
	require.Equal(t, "https://example.com", loadedCfg.ResumeFrom, "Loaded target should match")
}

func TestResumeCfg_ContiguousCompletionTracking(t *testing.T) {
	cfg := &ResumeCfg{}

	// Dispatch 5 items
	targets := []string{"t1", "t2", "t3", "t4", "t5"}
	for _, target := range targets {
		_, skip := cfg.NextIndex(target)
		require.False(t, skip)
	}

	// Complete item 1 -> index should be 1
	cfg.MarkCompleted(1, "t1")
	idx, tgt := cfg.CurrentCompleted()
	require.Equal(t, 1, idx)
	require.Equal(t, "t1", tgt)

	// Complete item 3 out-of-order -> index should still remain 1 because item 2 is in-flight
	cfg.MarkCompleted(3, "t3")
	idx, tgt = cfg.CurrentCompleted()
	require.Equal(t, 1, idx, "Index must not advance past incomplete in-flight item 2")
	require.Equal(t, "t1", tgt)

	// Complete item 5 out-of-order -> index should still be 1
	cfg.MarkCompleted(5, "t5")
	idx, tgt = cfg.CurrentCompleted()
	require.Equal(t, 1, idx)
	require.Equal(t, "t1", tgt)

	// Complete item 2 -> index should jump to 3 (since 1, 2, 3 are now all done, but 4 is still in-flight)
	cfg.MarkCompleted(2, "t2")
	idx, tgt = cfg.CurrentCompleted()
	require.Equal(t, 3, idx, "Index should advance to 3 after missing item 2 completes")
	require.Equal(t, "t3", tgt)

	// Complete item 4 -> index should jump to 5 (since 4 and 5 are now complete)
	cfg.MarkCompleted(4, "t4")
	idx, tgt = cfg.CurrentCompleted()
	require.Equal(t, 5, idx, "Index should advance to 5 once all items complete")
	require.Equal(t, "t5", tgt)
}

func TestRunner_MultiThreadedInterruptAndResume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interrupt-and-resume integration test in short mode")
	}

	// Set up mock HTTP server
	var serverRequests int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverRequests, 1)
		// Small delay to simulate in-flight concurrency
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)

	tempDir := t.TempDir()
	resumeFile := filepath.Join(tempDir, "resume.cfg")

	// Generate target list with query params to create unique URLs pointing to local test server
	const totalTargets = 30
	var targets []string
	for i := 1; i <= totalTargets; i++ {
		targets = append(targets, fmt.Sprintf("%s:%s?id=%d", u.Hostname(), u.Port(), i))
	}

	var firstRunProcessed sync.Map
	var firstRunCount int32
	const interruptThreshold = 10

	opts1 := &Options{
		InputTargetHost: targets,
		Threads:         4,
		Delay:           0,
		NoColor:         true,
		resumeCfg:       &ResumeCfg{},
		OnResult: func(r Result) {
			if r.Err == nil {
				firstRunProcessed.Store(r.URL, true)
				atomic.AddInt32(&firstRunCount, 1)
			}
		},
	}

	r1, err := New(opts1)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r1.RunEnumeration()
	}()

	// Monitor progress and interrupt when threshold reached (with 60s timeout guard)
	deadline := time.After(60 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	interrupted := false
	for !interrupted {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for interrupt threshold")
		case <-ticker.C:
			if atomic.LoadInt32(&firstRunCount) >= interruptThreshold {
				r1.Interrupt()
				interrupted = true
			}
		}
	}

	wg.Wait()

	require.Less(t, atomic.LoadInt32(&firstRunCount), int32(totalTargets),
		"the interrupted run must leave targets for the resumed run")

	// Save resume config atomically to the temp resume file
	err = r1.options.resumeCfg.Save(resumeFile)
	require.NoError(t, err)
	require.True(t, fileutil.FileExists(resumeFile), "Resume file must exist")

	var savedCfg ResumeCfg
	err = goconfig.Load(&savedCfg, resumeFile)
	require.NoError(t, err)
	require.True(t, savedCfg.Index > 0, "Saved index must be greater than 0")
	require.NotEmpty(t, savedCfg.ResumeFrom, "Saved ResumeFrom must not be empty")

	// --- Resumed Scan ---
	var secondRunProcessed sync.Map
	opts2 := &Options{
		InputTargetHost: targets,
		Threads:         4,
		Delay:           0,
		NoColor:         true,
		Resume:          true,
		resumeCfg:       &ResumeCfg{Index: savedCfg.Index, ResumeFrom: savedCfg.ResumeFrom},
		OnResult: func(r Result) {
			if r.Err == nil {
				secondRunProcessed.Store(r.URL, true)
			}
		},
	}

	r2, err := New(opts2)
	require.NoError(t, err)

	r2.RunEnumeration()

	// Assert that across run 1 + run 2, 100% of targets were processed
	allProcessed := make(map[string]bool)
	firstRunProcessed.Range(func(key, value any) bool {
		allProcessed[key.(string)] = true
		return true
	})
	secondRunProcessed.Range(func(key, value any) bool {
		allProcessed[key.(string)] = true
		return true
	})

	require.Equal(t, totalTargets, len(allProcessed), "100% of targets must be processed with no targets dropped")
}
