package main

import (
	"os"

	"github.com/projectdiscovery/httpx/internal/testutils"
	"github.com/projectdiscovery/httpx/runner"
)

var libraryTestcases = map[string]testutils.TestCase{
	"Httpx as library": &httpxLibrary{},
}

type httpxLibrary struct {
}

func (h *httpxLibrary) Execute() error {
	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	options := runner.Options{
		Methods:   "GET",
		InputFile: testFile,
	}
	if err := options.ValidateOptions(); err != nil {
		return err
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return err
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
	return nil
}
