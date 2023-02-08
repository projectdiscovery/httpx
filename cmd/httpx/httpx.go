package main

import (
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	errorutil "github.com/projectdiscovery/utils/errors"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	// Profiling related code
	if options.Memprofile != "" {
		f, err := os.Create(options.Memprofile)
		if err != nil {
			gologger.Fatal().Msgf("profile: could not create memory profile %q: %v", options.Memprofile, err)
		}
		old := runtime.MemProfileRate
		runtime.MemProfileRate = 4096
		gologger.Print().Msgf("profile: memory profiling enabled (rate %d), %s", runtime.MemProfileRate, options.Memprofile)

		defer func() {
			_ = pprof.Lookup("heap").WriteTo(f, 0)
			f.Close()
			runtime.MemProfileRate = old
			gologger.Print().Msgf("profile: memory profiling disabled, %s", options.Memprofile)
		}()
	}

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

func init() {
	if os.Getenv("DEBUG") != "" {
		errorutil.ShowStackTrace = true
	}
}
