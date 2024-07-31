package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/internal/pdcp"
	"github.com/projectdiscovery/httpx/runner"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	_ "github.com/projectdiscovery/utils/pprof"
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

	// validation for local results file upload
	if options.AssetFileUpload != "" {
		_ = setupOptionalAssetUpload(options)
		file, err := os.Open(options.AssetFileUpload)
		if err != nil {
			gologger.Fatal().Msgf("Could not open file: %s\n", err)
		}
		defer file.Close()
		dec := json.NewDecoder(file)
		for dec.More() {
			var r runner.Result
			err := dec.Decode(&r)
			if err != nil {
				gologger.Fatal().Msgf("Could not decode jsonl file: %s\n", err)
			}
			options.OnResult(r)
		}
		options.OnClose()
		return
	}

	// setup optional asset upload
	_ = setupOptionalAssetUpload(options)

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

// setupOptionalAssetUpload is used to setup optional asset upload
// this is optional and only initialized when explicitly enabled
func setupOptionalAssetUpload(opts *runner.Options) *pdcp.UploadWriter {
	var mustEnable bool
	// enable on multiple conditions
	if opts.AssetUpload || opts.AssetID != "" || opts.AssetName != "" || pdcp.EnableCloudUpload {
		mustEnable = true
	}
	a := aurora.NewAurora(!opts.NoColor)
	if !mustEnable {
		if !pdcp.HideAutoSaveMsg {
			gologger.Print().Msgf("[%s] UI Dashboard is disabled, Use -dashboard option to enable", a.BrightYellow("WRN"))
		}
		return nil
	}
	if opts.Screenshot {
		gologger.Fatal().Msgf("Screenshot option is not supported for dashboard upload yet")
	}
	gologger.Info().Msgf("To view results in UI dashboard, visit https://cloud.projectdiscovery.io/assets upon completion.")
	h := &pdcpauth.PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err != nil {
		if err != pdcpauth.ErrNoCreds && !pdcp.HideAutoSaveMsg {
			gologger.Verbose().Msgf("Could not get credentials for cloud upload: %s\n", err)
		}
		pdcpauth.CheckNValidateCredentials("httpx")
		return nil
	}
	writer, err := pdcp.NewUploadWriterCallback(context.Background(), creds)
	if err != nil {
		gologger.Error().Msgf("failed to setup UI dashboard: %s", err)
		return nil
	}
	if writer == nil {
		gologger.Error().Msgf("something went wrong, could not setup UI dashboard")
	}
	opts.OnResult = writer.GetWriterCallback()
	opts.OnClose = func() {
		writer.Close()
	}
	// add additional metadata
	if opts.AssetID != "" {
		// silently ignore
		_ = writer.SetAssetID(opts.AssetID)
	}
	if opts.AssetName != "" {
		// silently ignore
		writer.SetAssetGroupName(opts.AssetName)
	}
	return writer
}
