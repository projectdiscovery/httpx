package runner

import (
	"flag"
	"os"
	"regexp"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/customheader"
	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/stringz"
)

const (
	maxFileNameLenght = 255
	two               = 2
)

type scanOptions struct {
	Methods                []string
	StoreResponseDirectory string
	RequestURI             string
	RequestBody            string
	VHost                  bool
	OutputTitle            bool
	OutputStatusCode       bool
	OutputLocation         bool
	OutputContentLength    bool
	StoreResponse          bool
	OutputServerHeader     bool
	OutputWebSocket        bool
	OutputWithNoColor      bool
	OutputMethod           bool
	ResponseInStdout       bool
	TLSProbe               bool
	CSPProbe               bool
	OutputContentType      bool
	Unsafe                 bool
	Pipeline               bool
	HTTP2Probe             bool
	OutputIP               bool
	OutputCName            bool
	OutputCDN              bool
	OutputResponseTime     bool
	PreferHTTPS            bool
	NoFallback             bool
}

// Options contains configuration options for chaos client.
type Options struct {
	CustomHeaders             customheader.CustomHeaders
	CustomPorts               customport.CustomPorts
	matchStatusCode           []int
	matchContentLength        []int
	filterStatusCode          []int
	filterContentLength       []int
	Output                    string
	StoreResponseDir          string
	HTTPProxy                 string
	SocksProxy                string
	InputFile                 string
	Methods                   string
	RequestURI                string
	OutputMatchStatusCode     string
	OutputMatchContentLength  string
	OutputFilterStatusCode    string
	OutputFilterContentLength string
	InputRawRequest           string
	rawRequest                string
	RequestBody               string
	OutputFilterString        string
	OutputMatchString         string
	OutputFilterRegex         string
	OutputMatchRegex          string
	Retries                   int
	Threads                   int
	Timeout                   int
	filterRegex               *regexp.Regexp
	matchRegex                *regexp.Regexp
	VHost                     bool
	Smuggling                 bool
	ExtractTitle              bool
	StatusCode                bool
	Location                  bool
	ContentLength             bool
	FollowRedirects           bool
	StoreResponse             bool
	JSONOutput                bool
	Silent                    bool
	Version                   bool
	Verbose                   bool
	NoColor                   bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	responseInStdout          bool
	FollowHostRedirects       bool
	OutputMethod              bool
	TLSProbe                  bool
	CSPProbe                  bool
	OutputContentType         bool
	OutputIP                  bool
	OutputCName               bool
	Unsafe                    bool
	Debug                     bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputCDN                 bool
	OutputResponseTime        bool
	NoFallback                bool
	protocol                  string
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
	flag.BoolVar(&options.StatusCode, "status-code", false, "Extracts status code")
	flag.BoolVar(&options.Location, "location", false, "Extracts location header")
	flag.Var(&options.CustomHeaders, "H", "Custom Header")
	flag.Var(&options.CustomPorts, "ports", "ports range (nmap syntax: eg 1,2-10,11)")
	flag.BoolVar(&options.ContentLength, "content-length", false, "Extracts content length")
	flag.BoolVar(&options.StoreResponse, "sr", false, "Save response to file (default 'output')")
	flag.StringVar(&options.StoreResponseDir, "srd", "output", "Save response directory")
	flag.BoolVar(&options.FollowRedirects, "follow-redirects", false, "Follow Redirects")
	flag.BoolVar(&options.FollowHostRedirects, "follow-host-redirects", false, "Only follow redirects on the same host")
	flag.StringVar(&options.HTTPProxy, "http-proxy", "", "HTTP Proxy, eg http://127.0.0.1:8080")
	flag.BoolVar(&options.JSONOutput, "json", false, "JSON Output")
	flag.StringVar(&options.InputFile, "l", "", "File containing domains")
	flag.StringVar(&options.Methods, "x", "", "Request Methods, use ALL to check all verbs ()")
	flag.BoolVar(&options.OutputMethod, "method", false, "Output method")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&options.Version, "version", false, "Show version of httpx")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose Mode")
	flag.BoolVar(&options.NoColor, "no-color", false, "No Color")
	flag.BoolVar(&options.OutputServerHeader, "web-server", false, "Extracts server header")
	flag.BoolVar(&options.OutputWebSocket, "websocket", false, "Prints out if the server exposes a websocket")
	flag.BoolVar(&options.responseInStdout, "response-in-json", false, "Server response directly in the tool output (-json only)")
	flag.BoolVar(&options.TLSProbe, "tls-probe", false, "Send HTTP probes on the extracted TLS domains")
	flag.BoolVar(&options.CSPProbe, "csp-probe", false, "Send HTTP probes on the extracted CSP domains")
	flag.StringVar(&options.RequestURI, "path", "", "Request path/file (example '/api')")
	flag.BoolVar(&options.OutputContentType, "content-type", false, "Extracts content-type")
	flag.StringVar(&options.OutputMatchStatusCode, "mc", "", "Match status code")
	flag.StringVar(&options.OutputMatchStatusCode, "ml", "", "Match content length")
	flag.StringVar(&options.OutputFilterStatusCode, "fc", "", "Filter status code")
	flag.StringVar(&options.OutputFilterContentLength, "fl", "", "Filter content length")
	flag.StringVar(&options.InputRawRequest, "request", "", "File containing raw request")
	flag.BoolVar(&options.Unsafe, "unsafe", false, "Send raw requests skipping golang normalization")
	flag.StringVar(&options.RequestBody, "body", "", "Request Body")
	flag.BoolVar(&options.Debug, "debug", false, "Debug mode")
	flag.BoolVar(&options.Pipeline, "pipeline", false, "HTTP1.1 Pipeline")
	flag.BoolVar(&options.HTTP2Probe, "http2", false, "HTTP2 probe")
	flag.BoolVar(&options.OutputIP, "ip", false, "Output target ip")
	flag.StringVar(&options.OutputFilterString, "filter-string", "", "Filter String")
	flag.StringVar(&options.OutputMatchString, "match-string", "", "Match string")
	flag.StringVar(&options.OutputFilterRegex, "filter-regex", "", "Filter Regex")
	flag.StringVar(&options.OutputMatchRegex, "match-regex", "", "Match Regex")
	flag.BoolVar(&options.OutputCName, "cname", false, "Output first cname")
	flag.BoolVar(&options.OutputCDN, "cdn", false, "Check if domain's ip belongs to known CDN (akamai, cloudflare, ..)")
	flag.BoolVar(&options.OutputResponseTime, "response-time", false, "Output the response time")
	flag.BoolVar(&options.NoFallback, "no-fallback", false, "If HTTPS on port 443 is successful on default configuration, probes also port 80 for HTTP")

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

	if options.InputRawRequest != "" && !fileutil.FileExists(options.InputRawRequest) {
		gologger.Fatalf("File %s does not exist!\n", options.InputRawRequest)
	}

	var err error
	if options.matchStatusCode, err = stringz.StringToSliceInt(options.OutputMatchStatusCode); err != nil {
		gologger.Fatalf("Invalid value for match status code option: %s\n", err)
	}
	if options.matchContentLength, err = stringz.StringToSliceInt(options.OutputMatchContentLength); err != nil {
		gologger.Fatalf("Invalid value for match content length option: %s\n", err)
	}
	if options.filterStatusCode, err = stringz.StringToSliceInt(options.OutputFilterStatusCode); err != nil {
		gologger.Fatalf("Invalid value for filter status code option: %s\n", err)
	}
	if options.filterContentLength, err = stringz.StringToSliceInt(options.OutputFilterContentLength); err != nil {
		gologger.Fatalf("Invalid value for filter content length option: %s\n", err)
	}
	if options.OutputFilterRegex != "" {
		if options.filterRegex, err = regexp.Compile(options.OutputFilterRegex); err != nil {
			gologger.Fatalf("Invalid value for regex filter option: %s\n", err)
		}
	}
	if options.OutputMatchRegex != "" {
		if options.matchRegex, err = regexp.Compile(options.OutputMatchRegex); err != nil {
			gologger.Fatalf("Invalid value for match regex option: %s\n", err)
		}
	}
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.MaxLevel = gologger.Verbose
	}
	if options.Debug {
		gologger.MaxLevel = gologger.Debug
	}
	if options.NoColor {
		gologger.UseColors = false
	}
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
