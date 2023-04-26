package fileutil

import (
	"bufio"
	"errors"

	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/projectdiscovery/httpx/common/stringz"
	fileutil "github.com/projectdiscovery/utils/file"
)

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

func LoadCidrsFromSliceOrFileWithMaxRecursion(option string, splitchar string, maxRecursion int) (networkList []string) {
	if maxRecursion < 0 {
		return
	}
	items := stringz.SplitByCharAndTrimSpace(option, splitchar)
	for _, item := range items {
		if net.ParseIP(item) != nil {
			networkList = append(networkList, item)
		} else if _, _, err := net.ParseCIDR(item); err == nil {
			networkList = append(networkList, item)
		} else if fileutil.FileExists(item) {
			if filedata, err := os.ReadFile(item); err == nil && len(filedata) > 0 {
				networkList = append(networkList, LoadCidrsFromSliceOrFileWithMaxRecursion(string(filedata), "\n", maxRecursion-1)...)
			}
		}
	}

	return
}

func AbsPathOrDefault(p string) string {
	if absPath, err := filepath.Abs(p); err == nil {
		return absPath
	}
	return p
}
