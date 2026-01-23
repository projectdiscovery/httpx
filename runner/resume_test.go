package runner

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/projectdiscovery/goconfig"
	"github.com/stretchr/testify/require"
)

func TestResumeCfg_TrackItemStart(t *testing.T) {
	cfg := &ResumeCfg{}
	cfg.SetThreadCount(4)

	idx1 := cfg.TrackItemStart("target1")
	require.Equal(t, 1, idx1)
	require.Equal(t, "target1", cfg.GetCurrentTarget())

	idx2 := cfg.TrackItemStart("target2")
	require.Equal(t, 2, idx2)
	require.Equal(t, "target2", cfg.GetCurrentTarget())

	idx3 := cfg.TrackItemStart("target3")
	require.Equal(t, 3, idx3)
	require.Equal(t, "target3", cfg.GetCurrentTarget())
}

func TestResumeCfg_GetSafeResumeIndex(t *testing.T) {
	tests := []struct {
		name         string
		threadCount  int
		itemsStarted int
		expected     int
	}{
		{
			name:         "no items started",
			threadCount:  4,
			itemsStarted: 0,
			expected:     0,
		},
		{
			name:         "fewer items than threads",
			threadCount:  4,
			itemsStarted: 2,
			expected:     0,
		},
		{
			name:         "items equal to threads",
			threadCount:  4,
			itemsStarted: 4,
			expected:     0,
		},
		{
			name:         "more items than threads",
			threadCount:  4,
			itemsStarted: 10,
			expected:     6,
		},
		{
			name:         "single thread",
			threadCount:  1,
			itemsStarted: 5,
			expected:     4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &ResumeCfg{}
			cfg.SetThreadCount(tc.threadCount)

			for i := 0; i < tc.itemsStarted; i++ {
				cfg.TrackItemStart("target")
			}

			got := cfg.GetSafeResumeIndex()
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestResumeCfg_ShouldSkip(t *testing.T) {
	cfg := &ResumeCfg{
		Index: 5,
	}

	tests := []struct {
		index    int
		expected bool
	}{
		{1, true},
		{5, true},
		{6, false},
		{10, false},
	}

	for _, tc := range tests {
		got := cfg.ShouldSkip(tc.index)
		require.Equal(t, tc.expected, got, "ShouldSkip(%d) = %v, want %v", tc.index, got, tc.expected)
	}
}

func TestResumeCfg_ConcurrentAccess(t *testing.T) {
	cfg := &ResumeCfg{}
	cfg.SetThreadCount(10)

	var wg sync.WaitGroup
	numGoroutines := 100

	wg.Add(numGoroutines)
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			cfg.TrackItemStart("target")
			_ = cfg.GetSafeResumeIndex()
			_ = cfg.GetCurrentTarget()
		}(i)
	}
	wg.Wait()

	require.Equal(t, numGoroutines, cfg.currentIndex)
}

func TestResumeFileSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	resumeFile := filepath.Join(tmpDir, "resume.cfg")

	type resumeFileFormat struct {
		ResumeFrom string
		Index      int
	}

	original := resumeFileFormat{
		ResumeFrom: "example.com",
		Index:      42,
	}

	err := goconfig.Save(original, resumeFile)
	require.NoError(t, err)

	loaded := &ResumeCfg{}
	err = goconfig.Load(&loaded, resumeFile)
	require.NoError(t, err)

	require.Equal(t, original.Index, loaded.Index)
	require.Equal(t, original.ResumeFrom, loaded.ResumeFrom)
}

func TestResumeIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	cfg := &ResumeCfg{}
	cfg.SetThreadCount(4)

	targets := []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com", "h.com", "i.com", "j.com"}
	for _, target := range targets {
		cfg.TrackItemStart(target)
	}

	type resumeFileFormat struct {
		ResumeFrom string
		Index      int
	}
	saveData := resumeFileFormat{
		Index:      cfg.GetSafeResumeIndex(),
		ResumeFrom: cfg.GetCurrentTarget(),
	}
	err := goconfig.Save(saveData, DefaultResumeFile)
	require.NoError(t, err)

	loadedCfg := &ResumeCfg{}
	err = goconfig.Load(&loadedCfg, DefaultResumeFile)
	require.NoError(t, err)

	require.Equal(t, 6, loadedCfg.Index)

	skipped := 0
	processed := 0
	for i := range targets {
		itemIndex := i + 1
		if loadedCfg.ShouldSkip(itemIndex) {
			skipped++
		} else {
			processed++
		}
	}

	require.Equal(t, 6, skipped)
	require.Equal(t, 4, processed)
}
