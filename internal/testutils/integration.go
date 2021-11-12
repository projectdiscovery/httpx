package testutils

import (
	"os"
	"os/exec"
	"strings"
	"fmt"
)

// RunNucleiAndGetResults returns a list of results for a template
func RunHttpxAndGetResults(url string, debug bool, extra ...string) ([]string, error) {
	cmd := exec.Command("bash", "-c")
	cmdLine := `echo "` + url + `" | ./httpx `
	cmdLine += strings.Join(extra, " ")
	if debug {
		cmdLine += " -debug"
		cmd.Stderr = os.Stderr
	} else {
		cmdLine += " -silent"
	}

	cmd.Args = append(cmd.Args, cmdLine)

	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	parts := []string{}
	items := strings.Split(string(data), "\n")
	for _, i := range items {
		if i != "" {
			parts = append(parts, i)
		}
	}
	return parts, nil
}
func RunHttpxBinaryAndGetResults(target string, httpxBinary string, debug bool, args []string) ([]string, error) {
	cmd := exec.Command("bash", "-c")
	cmdLine := fmt.Sprintf(`echo %s | %s `, target, httpxBinary)
	cmdLine += strings.Join(args, " ")
	if debug {
		cmdLine += " -debug"
		cmd.Stderr = os.Stderr
	} else {
		cmdLine += " -silent"
	}

	cmd.Args = append(cmd.Args, cmdLine)
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	parts := []string{}
	items := strings.Split(string(data), "\n")
	for _, i := range items {
		if i != "" {
			parts = append(parts, i)
		}
	}
	return parts,nil
}

// TestCase is a single integration test case
type TestCase interface {
	// Execute executes a test case and returns any errors if occurred
	Execute() error
}
