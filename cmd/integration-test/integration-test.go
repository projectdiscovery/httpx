package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/httpx/internal/testutils"
)

var (
	debug      = os.Getenv("DEBUG") == "true"
	customTest = os.Getenv("TEST")
	protocol   = os.Getenv("PROTO")

	errored = false
)

func main() {
	success := aurora.Green("[✓]").String()
	failed := aurora.Red("[✘]").String()

	tests := map[string]map[string]testutils.TestCase{
		"http":    httpTestcases,
		"library": libraryTestcases,
	}
	for proto, tests := range tests {
		if protocol == "" || protocol == proto {
			fmt.Printf("Running test cases for \"%s\"\n", aurora.Blue(proto))

			for name, test := range tests {
				if customTest != "" && !strings.Contains(name, customTest) {
					continue // only run tests user asked
				}
				err := test.Execute()
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, name, err)
					errored = true
				} else {
					fmt.Printf("%s Test \"%s\" passed!\n", success, name)
				}
			}
		}
	}
	if errored {
		os.Exit(1)
	}
}

func errIncorrectResultsCount(results []string) error {
	return fmt.Errorf("incorrect number of results %s", strings.Join(results, "\n\t"))
}

func errIncorrectResult(expected, got string) error {
	return fmt.Errorf("incorrect result: expected \"%s\" got \"%s\"", expected, got)
}
