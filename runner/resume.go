package runner

import "sync"

type ResumeCfg struct {
	ResumeFrom     string
	Index          int
	current        string
	currentIndex   int
	completedIndex int
	completedInput string
	mu             sync.Mutex
}
