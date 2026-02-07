package runner

import "sync"

type ResumeCfg struct {
	ResumeFrom   string
	Index        int
	current      string
	currentIndex int
	// lastCompletedIndex tracks the index of the last item that was fully processed
	// This ensures we don't skip items that were in-progress when interrupted
	lastCompletedIndex int
	lastCompletedItem  string
	// mu protects lastCompletedIndex and lastCompletedItem from concurrent access
	mu sync.Mutex
}

// SetLastCompleted safely updates the last completed item state
func (r *ResumeCfg) SetLastCompleted(index int, item string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastCompletedIndex = index
	r.lastCompletedItem = item
}

// GetLastCompleted safely retrieves the last completed item state
func (r *ResumeCfg) GetLastCompleted() (int, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastCompletedIndex, r.lastCompletedItem
}
