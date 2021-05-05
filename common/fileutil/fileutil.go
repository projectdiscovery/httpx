package fileutil

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) || err != nil || info == nil {
		return false
	}
	return !info.IsDir()
}

// FolderExists checks if a folder exists
func FolderExists(folderpath string) bool {
	_, err := os.Stat(folderpath)
	return !os.IsNotExist(err)
}

// HasStdin determines if the user has piped input
func HasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	mode := stat.Mode()

	isPipedFromChrDev := (mode & os.ModeCharDevice) == 0
	isPipedFromFIFO := (mode & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

// LoadFile content to slice
func LoadFile(filename string) (lines []string) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close() //nolint
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}

	return
}

// ListFilesWithPattern in a root folder
func ListFilesWithPattern(rootpattern string) ([]string, error) {
	files, err := filepath.Glob(rootpattern)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no files found")
	}
	return files, err
}

// FileNameIsGlob check if the filanem is a pattern
func FileNameIsGlob(pattern string) bool {
	_, err := regexp.Compile(pattern)
	return err == nil
}
