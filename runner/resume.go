package runner

import "sync"

type ResumeCfg struct {
	ResumeFrom   string
	Index        int
	current      string
	currentIndex int
	threadCount  int

	mu sync.Mutex
}

// SetThreadCount sets the thread count for safe resume index calculation
func (cfg *ResumeCfg) SetThreadCount(threads int) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	cfg.threadCount = threads
}

// TrackItemStart is called when an item starts processing.
// Returns the index assigned to this item.
func (cfg *ResumeCfg) TrackItemStart(target string) int {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	cfg.current = target
	cfg.currentIndex++
	return cfg.currentIndex
}

// GetSafeResumeIndex returns a conservative resume index that accounts for
// potentially in-flight items. This ensures we don't skip incomplete items.
// Since items are dispatched to async workers, we subtract the thread count
// as a safety margin to account for items that may not have completed.
func (cfg *ResumeCfg) GetSafeResumeIndex() int {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	safetyMargin := cfg.threadCount
	if safetyMargin < 1 {
		safetyMargin = 1
	}

	safeIndex := cfg.currentIndex - safetyMargin
	if safeIndex < 0 {
		return 0
	}
	return safeIndex
}

// GetCurrentTarget returns the current target being processed.
func (cfg *ResumeCfg) GetCurrentTarget() string {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	return cfg.current
}

// ShouldSkip returns true if the item at the given index should be skipped during resume.
func (cfg *ResumeCfg) ShouldSkip(index int) bool {
	return index <= cfg.Index
}
