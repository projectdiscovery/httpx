package main

import (
	"net/http"
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

	var got string

	options := runner.Options{
		Methods:   http.MethodGet,
		InputFile: testFile,
		OnResult: func(r runner.Result) {
			got = r.URL
		},
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

	// httpx removes default ports for simplicity Ref: https://pkg.go.dev/github.com/projectdiscovery/httpx/common/stringz#RemoveURLDefaultPort
	expected := "https://scanme.sh"

	if got != expected {
		return errIncorrectResult(expected, got)
	}

	return nil
}
