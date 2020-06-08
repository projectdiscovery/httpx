package main

import (
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/customheader"
	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/common/fileutil"
)

// Options contains configuration options for chaos client.
type Options struct {
	RawRequestFile     string
	VHost              bool
	Smuggling          bool
	ExtractTitle       bool
	StatusCode         bool
	ContentLength      bool
	Retries            int
	Threads            int
	Timeout            int
	CustomHeaders      customheader.CustomHeaders
	CustomPorts        customport.CustomPorts
	Output             string
	FollowRedirects    bool
	StoreResponse      bool
	StoreResponseDir   string
	HttpProxy          string
	SocksProxy         string
	JSONOutput         bool
	InputFile          string
	Method             string
	Silent             bool
	Version            bool
	Verbose            bool
	NoColor            bool
	OutputServerHeader bool
	responseInStdout bool
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}

	flag.IntVar(&options.Threads, "threads", 50, "Number of threads")
	flag.IntVar(&options.Retries, "retries", 0, "Number of retries")
	flag.IntVar(&options.Timeout, "timeout", 5, "Timeout in seconds")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.BoolVar(&options.VHost, "vhost", false, "Check for VHOSTs")
	flag.BoolVar(&options.ExtractTitle, "title", false, "Extracts title")
	flag.BoolVar(&options.StatusCode, "status-code", false, "Extracts Status Code")
	flag.Var(&options.CustomHeaders, "H", "Custom Header")
	flag.Var(&options.CustomPorts, "ports", "ports range (nmap syntax: eg 1,2-10,11)")
	flag.BoolVar(&options.ContentLength, "content-length", false, "Content Length")
	flag.BoolVar(&options.StoreResponse, "store-response", false, "Store Response as domain.txt")
	flag.StringVar(&options.StoreResponseDir, "store-response-dir", ".", "Store Response Directory (default current directory)")
	flag.BoolVar(&options.FollowRedirects, "follow-redirects", false, "Follow Redirects")
	flag.StringVar(&options.HttpProxy, "http-proxy", "", "Http Proxy")
	flag.BoolVar(&options.JSONOutput, "json", false, "JSON Output")
	flag.StringVar(&options.InputFile, "l", "", "File containing domains")
	flag.StringVar(&options.Method, "x", "GET", "Request Method")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&options.Version, "version", false, "Show version of httpx")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose Mode")
	flag.BoolVar(&options.NoColor, "no-color", false, "No Color")
	flag.BoolVar(&options.OutputServerHeader, "web-server", false, "Prints out the Server header content")
	flag.BoolVar(&options.responseInStdout, "response-in-json", false, "Server response directly in the tool output (-json only)")
	flag.Parse()

	// Read the inputs and configure the logging
	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Infof("Current Version: %s\n", Version)
		os.Exit(0)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.InputFile != "" && !fileutil.FileExists(options.InputFile) {
		gologger.Fatalf("File %s does not exist!\n", options.InputFile)
	}
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.MaxLevel = gologger.Verbose
	}
	if options.NoColor {
		gologger.UseColors = false
	}
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
