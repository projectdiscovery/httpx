package runner

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveAtomic(t *testing.T) {
	tempDir := t.TempDir()
	targetPath := filepath.Join(tempDir, "test_resume.cfg")

	// 1. Basic atomic write
	data := []byte("resume_index: 42\nresume_from: example.com\n")
	err := SaveAtomic(targetPath, data)
	require.NoError(t, err)

	readData, err := os.ReadFile(targetPath)
	require.NoError(t, err)
	require.Equal(t, data, readData)

	// 2. Overwrite atomically
	newData := []byte("resume_index: 100\nresume_from: target.org\n")
	err = SaveAtomic(targetPath, newData)
	require.NoError(t, err)

	readData, err = os.ReadFile(targetPath)
	require.NoError(t, err)
	require.Equal(t, newData, readData)

	// 3. Concurrent saves
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := []byte("concurrent_data")
			_ = SaveAtomic(targetPath, payload)
		}(i)
	}
	wg.Wait()

	finalData, err := os.ReadFile(targetPath)
	require.NoError(t, err)
	require.Equal(t, []byte("concurrent_data"), finalData)
}
