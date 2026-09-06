package runner

import (
	"encoding/json"
	"os"
)

// SaveAtomic performs atomic file replacement on POSIX and Windows
func SaveAtomic(filePath string, data interface{}) error {
	tmpFile := filePath + ".tmp"
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpFile, raw, 0644); err != nil {
		return err
	}
	return os.Rename(tmpFile, filePath)
}
