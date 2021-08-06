package main

import (
	"os"
	"os/signal"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	httpxRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			httpxRunner.Close()
			if options.ShouldSaveResume() {
				gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFile)
				err := httpxRunner.SaveResumeConfig()
				if err != nil {
					gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
				}
			}
			os.Exit(1)
		}
	}()

	httpxRunner.RunEnumeration()
	httpxRunner.Close()
}
