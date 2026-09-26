package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SaveAtomic safely writes data to a unique temporary file before renaming to targetPath.
func SaveAtomic(targetPath string, data interface{}) error {
	dir := filepath.Dir(targetPath)
	tmpFile, err := os.CreateTemp(dir, "resume-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	raw, err := json.Marshal(data)
	if err != nil {
		tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(raw); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpFile.Name(), targetPath)
}
