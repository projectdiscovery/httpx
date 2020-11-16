package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/internal/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	run, err := runner.New(options)
	if err != nil {
		gologger.Fatalf("Could not create runner: %s\n", err)
	}

	run.RunEnumeration()
	run.Close()
}
