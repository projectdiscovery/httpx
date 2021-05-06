package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	r, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	r.RunEnumeration()
	r.Close()
}
