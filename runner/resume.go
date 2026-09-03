package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/projectdiscovery/goconfig"
)

type resumeSaveState struct {
	ResumeFrom string `json:"resumeFrom,omitempty"`
	Index      int    `json:"index,omitempty"`
}

type ResumeCfg struct {
	sync.RWMutex    `json:"-"`
	ResumeFrom      string         `json:"resumeFrom,omitempty"`
	Index           int            `json:"index,omitempty"`
	resumeBaseline  int
	current         string
	currentIndex    int
	completed       map[int]string
	completedIdx    int
	completedTarget string
}

func (r *ResumeCfg) init() {
	if r.completed == nil {
		r.completed = make(map[int]string)
		r.completedIdx = r.Index
		r.completedTarget = r.ResumeFrom
		r.resumeBaseline = r.Index
	}
}

// NextIndex increments the dispatched index and returns whether the item should be skipped.
func (r *ResumeCfg) NextIndex(target string) (int, bool) {
	r.Lock()
	defer r.Unlock()
	r.init()

	r.currentIndex++
	r.current = target

	if r.currentIndex <= r.resumeBaseline {
		return r.currentIndex, true
	}
	return r.currentIndex, false
}

// MarkCompleted records that an item at the given index has fully finished processing.
func (r *ResumeCfg) MarkCompleted(index int, target string) {
	r.Lock()
	defer r.Unlock()
	r.init()

	r.completed[index] = target

	for {
		nextIdx := r.completedIdx + 1
		if tgt, exists := r.completed[nextIdx]; exists {
			r.completedIdx = nextIdx
			r.completedTarget = tgt
			delete(r.completed, nextIdx)
		} else {
			break
		}
	}

	r.Index = r.completedIdx
	r.ResumeFrom = r.completedTarget
}

// CurrentCompleted returns the current contiguous completed index and target.
func (r *ResumeCfg) CurrentCompleted() (int, string) {
	r.RLock()
	defer r.RUnlock()
	return r.Index, r.ResumeFrom
}

// Save atomically writes the ResumeCfg to the specified file path.
func (r *ResumeCfg) Save(filePath string) error {
	r.RLock()
	state := resumeSaveState{
		ResumeFrom: r.ResumeFrom,
		Index:      r.Index,
	}
	r.RUnlock()

	dir := filepath.Dir(filePath)
	if dir == "" {
		dir = "."
	}
	tempFile, err := os.CreateTemp(dir, fmt.Sprintf(".%s-*.tmp", filepath.Base(filePath)))
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	_ = tempFile.Close()

	if err := goconfig.Save(state, tempPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	if f, err := os.OpenFile(tempPath, os.O_RDWR, 0600); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}

	if err := os.Rename(tempPath, filePath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	return nil
}
