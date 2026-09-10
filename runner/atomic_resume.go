package runner

import (
	"os"
	"path/filepath"
	"sync"
)

var atomicResumeMutex sync.Mutex

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

	return os.Rename(tmpName, targetPath)
}
