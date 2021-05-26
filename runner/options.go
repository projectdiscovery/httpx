package runner

import (
	"flag"
	"math"
	"os"
	"regexp"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/common/customlist"
	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/stringz"
)

const (
	maxFileNameLength = 255
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
	ChainInStdout          bool
	TLSProbe               bool
	CSPProbe               bool
	VHostInput             bool
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
	NoFallbackScheme       bool
	TechDetect             bool
	StoreChain             bool
	MaxResponseBodySize    int
	OutputExtractRegex     string
	extractRegex           *regexp.Regexp
}

func (s *scanOptions) Clone() *scanOptions {
	return &scanOptions{
		Methods:                s.Methods,
		StoreResponseDirectory: s.StoreResponseDirectory,
		RequestURI:             s.RequestURI,
		RequestBody:            s.RequestBody,
		VHost:                  s.VHost,
		OutputTitle:            s.OutputTitle,
		OutputStatusCode:       s.OutputStatusCode,
		OutputLocation:         s.OutputLocation,
		OutputContentLength:    s.OutputContentLength,
		StoreResponse:          s.StoreResponse,
		OutputServerHeader:     s.OutputServerHeader,
		OutputWebSocket:        s.OutputWebSocket,
		OutputWithNoColor:      s.OutputWithNoColor,
		OutputMethod:           s.OutputMethod,
		ResponseInStdout:       s.ResponseInStdout,
		ChainInStdout:          s.ChainInStdout,
		TLSProbe:               s.TLSProbe,
		CSPProbe:               s.CSPProbe,
		OutputContentType:      s.OutputContentType,
		Unsafe:                 s.Unsafe,
		Pipeline:               s.Pipeline,
		HTTP2Probe:             s.HTTP2Probe,
		OutputIP:               s.OutputIP,
		OutputCName:            s.OutputCName,
		OutputCDN:              s.OutputCDN,
		OutputResponseTime:     s.OutputResponseTime,
		PreferHTTPS:            s.PreferHTTPS,
		NoFallback:             s.NoFallback,
		NoFallbackScheme:       s.NoFallbackScheme,
		TechDetect:             s.TechDetect,
		StoreChain:             s.StoreChain,
		OutputExtractRegex:     s.OutputExtractRegex,
	}
}

// Options contains configuration options for httpx.
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
	RequestURIs               string
	requestURIs               []string
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
	VHostInput                bool
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
	chainInStdout             bool
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
	NoFallbackScheme          bool
	TechDetect                bool
	TLSGrab                   bool
	protocol                  string
	ShowStatistics            bool
	RandomAgent               bool
	StoreChain                bool
	Deny                      customlist.CustomList
	Allow                     customlist.CustomList
	MaxResponseBodySize       int
	OutputExtractRegex        string
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}

	flag.BoolVar(&options.TLSGrab, "tls-grab", false, "Perform TLS data grabbing")
	flag.BoolVar(&options.TechDetect, "tech-detect", false, "Perform wappalyzer based technology detection")
	flag.IntVar(&options.Threads, "threads", 50, "Number of threads")
	flag.IntVar(&options.Retries, "retries", 0, "Number of retries")
	flag.IntVar(&options.Timeout, "timeout", 5, "Timeout in seconds")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.BoolVar(&options.VHost, "vhost", false, "Check for VHOSTs")
	flag.BoolVar(&options.VHostInput, "vhost-input", false, "Get a list of vhosts as input")
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
	flag.BoolVar(&options.OutputMethod, "method", false, "Display request method")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&options.Version, "version", false, "Show version of httpx")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose Mode")
	flag.BoolVar(&options.NoColor, "no-color", false, "No Color")
	flag.BoolVar(&options.OutputServerHeader, "web-server", false, "Extracts server header")
	flag.BoolVar(&options.OutputWebSocket, "websocket", false, "Prints out if the server exposes a websocket")
	flag.BoolVar(&options.responseInStdout, "response-in-json", false, "Show Raw HTTP Response In Output (-json only) (deprecated)")
	flag.BoolVar(&options.responseInStdout, "include-response", false, "Show Raw HTTP Response In Output (-json only)")
	flag.BoolVar(&options.chainInStdout, "include-chain", false, "Show Raw HTTP Chain In Output (-json only)")
	flag.BoolVar(&options.TLSProbe, "tls-probe", false, "Send HTTP probes on the extracted TLS domains")
	flag.BoolVar(&options.CSPProbe, "csp-probe", false, "Send HTTP probes on the extracted CSP domains")
	flag.StringVar(&options.RequestURI, "path", "", "Request path/file (example '/api')")
	flag.StringVar(&options.RequestURIs, "paths", "", "Command separated paths or file containing one path per line (example '/api/v1,/apiv2')")
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
	flag.BoolVar(&options.NoFallbackScheme, "no-fallback-scheme", false, "The tool will respect and attempt the scheme specified in the url (if HTTPS is specified no HTTP is attempted)")
	flag.BoolVar(&options.ShowStatistics, "stats", false, "Enable statistic on keypress (terminal may become unresponsive till the end)")
	flag.BoolVar(&options.RandomAgent, "random-agent", false, "Use randomly selected HTTP User-Agent header value")
	flag.BoolVar(&options.StoreChain, "store-chain", false, "Save chain to file (default 'output')")
	flag.Var(&options.Allow, "allow", "Allowlist ip/cidr")
	flag.Var(&options.Deny, "deny", "Denylist ip/cidr")
	flag.IntVar(&options.MaxResponseBodySize, "max-response-body-size", math.MaxInt32, "Maximum response body size")
	flag.StringVar(&options.OutputExtractRegex, "extract-regex", "", "Extract Regex")

	flag.Parse()

	// Read the inputs and configure the logging
	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.InputFile != "" && !fileutil.FileNameIsGlob(options.InputFile) && !fileutil.FileExists(options.InputFile) {
		gologger.Fatal().Msgf("File %s does not exist!\n", options.InputFile)
	}

	if options.InputRawRequest != "" && !fileutil.FileExists(options.InputRawRequest) {
		gologger.Fatal().Msgf("File %s does not exist!\n", options.InputRawRequest)
	}

	var err error
	if options.matchStatusCode, err = stringz.StringToSliceInt(options.OutputMatchStatusCode); err != nil {
		gologger.Fatal().Msgf("Invalid value for match status code option: %s\n", err)
	}
	if options.matchContentLength, err = stringz.StringToSliceInt(options.OutputMatchContentLength); err != nil {
		gologger.Fatal().Msgf("Invalid value for match content length option: %s\n", err)
	}
	if options.filterStatusCode, err = stringz.StringToSliceInt(options.OutputFilterStatusCode); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter status code option: %s\n", err)
	}
	if options.filterContentLength, err = stringz.StringToSliceInt(options.OutputFilterContentLength); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter content length option: %s\n", err)
	}
	if options.OutputFilterRegex != "" {
		if options.filterRegex, err = regexp.Compile(options.OutputFilterRegex); err != nil {
			gologger.Fatal().Msgf("Invalid value for regex filter option: %s\n", err)
		}
	}
	if options.OutputMatchRegex != "" {
		if options.matchRegex, err = regexp.Compile(options.OutputMatchRegex); err != nil {
			gologger.Fatal().Msgf("Invalid value for match regex option: %s\n", err)
		}
	}
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
