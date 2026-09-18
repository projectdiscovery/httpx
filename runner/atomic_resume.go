package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"gopkg.in/yaml.v3"
)

var atomicResumeMutex sync.Mutex

// syncDir attempts to fsync the directory containing targetPath on POSIX platforms.
func syncDir(dirPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func SaveAtomic(targetPath string, data []byte) error {
	atomicResumeMutex.Lock()
	defer atomicResumeMutex.Unlock()

	dir := filepath.Dir(targetPath)
	tmpFile, err := os.CreateTemp(dir, "httpx-resume-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, targetPath); err != nil {
		return err
	}

	return syncDir(dir)
}

// SaveResumeConfigAtomic serializes the resume config and writes it using SaveAtomic.
func (r *Runner) SaveResumeConfigAtomic() error {
	if r.options == nil || r.options.resumeCfg == nil {
		return nil
	}
	var resumeCfg ResumeCfg
	resumeCfg.Index = r.options.resumeCfg.currentIndex
	resumeCfg.ResumeFrom = r.options.resumeCfg.current
	data, err := yaml.Marshal(resumeCfg)
	if err != nil {
		return err
	}
	return SaveAtomic(DefaultResumeFile, data)
}
