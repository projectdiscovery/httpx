package runner

import (
	"flag"
	"math"
	"os"
	"regexp"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/common/customlist"
	customport "github.com/projectdiscovery/httpx/common/customports"
	fileutilz "github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/stringz"
)

const (
	maxFileNameLength = 255
	two               = 2
	DefaultResumeFile = "resume.cfg"
)

type scanOptions struct {
	Methods                   []string
	StoreResponseDirectory    string
	RequestURI                string
	RequestBody               string
	VHost                     bool
	OutputTitle               bool
	OutputStatusCode          bool
	OutputLocation            bool
	OutputContentLength       bool
	StoreResponse             bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	OutputWithNoColor         bool
	OutputMethod              bool
	ResponseInStdout          bool
	ChainInStdout             bool
	TLSProbe                  bool
	CSPProbe                  bool
	VHostInput                bool
	OutputContentType         bool
	Unsafe                    bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputIP                  bool
	OutputCName               bool
	OutputCDN                 bool
	OutputResponseTime        bool
	PreferHTTPS               bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	StoreChain                bool
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	extractRegex              *regexp.Regexp
	ExcludeCDN                bool
	HostMaxErrors             int
}

func (s *scanOptions) Clone() *scanOptions {
	return &scanOptions{
		Methods:                   s.Methods,
		StoreResponseDirectory:    s.StoreResponseDirectory,
		RequestURI:                s.RequestURI,
		RequestBody:               s.RequestBody,
		VHost:                     s.VHost,
		OutputTitle:               s.OutputTitle,
		OutputStatusCode:          s.OutputStatusCode,
		OutputLocation:            s.OutputLocation,
		OutputContentLength:       s.OutputContentLength,
		StoreResponse:             s.StoreResponse,
		OutputServerHeader:        s.OutputServerHeader,
		OutputWebSocket:           s.OutputWebSocket,
		OutputWithNoColor:         s.OutputWithNoColor,
		OutputMethod:              s.OutputMethod,
		ResponseInStdout:          s.ResponseInStdout,
		ChainInStdout:             s.ChainInStdout,
		TLSProbe:                  s.TLSProbe,
		CSPProbe:                  s.CSPProbe,
		OutputContentType:         s.OutputContentType,
		Unsafe:                    s.Unsafe,
		Pipeline:                  s.Pipeline,
		HTTP2Probe:                s.HTTP2Probe,
		OutputIP:                  s.OutputIP,
		OutputCName:               s.OutputCName,
		OutputCDN:                 s.OutputCDN,
		OutputResponseTime:        s.OutputResponseTime,
		PreferHTTPS:               s.PreferHTTPS,
		NoFallback:                s.NoFallback,
		NoFallbackScheme:          s.NoFallbackScheme,
		TechDetect:                s.TechDetect,
		StoreChain:                s.StoreChain,
		OutputExtractRegex:        s.OutputExtractRegex,
		MaxResponseBodySizeToSave: s.MaxResponseBodySizeToSave,
		MaxResponseBodySizeToRead: s.MaxResponseBodySizeToRead,
		HostMaxErrors:             s.HostMaxErrors,
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
	CSVOutput                 bool
	Silent                    bool
	Version                   bool
	Verbose                   bool
	NoColor                   bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	responseInStdout          bool
	chainInStdout             bool
	FollowHostRedirects       bool
	MaxRedirects              int
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
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	RateLimit                 int
	Probe                     bool
	Resume                    bool
	resumeCfg                 *ResumeCfg
	ExcludeCDN                bool
	HostMaxErrors             int
	Stream                    bool
	SkipDedupe                bool
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.BoolVar(&options.TLSGrab, "tls-grab", false, "Perform TLS(SSL) data grabbing")
	flag.BoolVar(&options.TechDetect, "tech-detect", false, "Perform wappalyzer based technology detection")
	flag.IntVar(&options.Threads, "threads", 50, "Number of threads")
	flag.IntVar(&options.Retries, "retries", 0, "Number of retries")
	flag.IntVar(&options.Timeout, "timeout", 5, "Timeout in seconds")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.BoolVar(&options.VHost, "vhost", false, "Check for VHOSTs")
	flag.BoolVar(&options.VHostInput, "vhost-input", false, "Get a list of vhosts as input")
	flag.BoolVar(&options.ExtractTitle, "title", false, "Display page title")
	flag.BoolVar(&options.StatusCode, "status-code", false, "Display HTTP response status code")
	flag.BoolVar(&options.Location, "location", false, "Display location header")
	flag.Var(&options.CustomHeaders, "H", "Custom Header to send with request")
	flag.Var(&options.CustomPorts, "ports", "Port ranges to scan (nmap syntax: eg 1,2-10,11)")
	flag.BoolVar(&options.ContentLength, "content-length", false, "Display HTTP response content length")
	flag.BoolVar(&options.StoreResponse, "sr", false, "Store HTTP response to directory (default 'output')")
	flag.StringVar(&options.StoreResponseDir, "srd", "output", "Custom directory to store HTTP responses")
	flag.BoolVar(&options.FollowRedirects, "follow-redirects", false, "Follow HTTP Redirects")
	flag.BoolVar(&options.FollowHostRedirects, "follow-host-redirects", false, "Only Follow redirects on the same host")
	flag.IntVar(&options.MaxRedirects, "max-redirects", 10, "Max number of redirects to follow per host")
	flag.StringVar(&options.HTTPProxy, "http-proxy", "", "HTTP Proxy, eg http://127.0.0.1:8080")
	flag.BoolVar(&options.JSONOutput, "json", false, "Display output in JSON format")
	flag.BoolVar(&options.CSVOutput, "csv", false, "Display output in CSV format")
	flag.StringVar(&options.InputFile, "l", "", "Input file containing list of hosts to process")
	flag.StringVar(&options.Methods, "x", "", "Request Methods to use, use 'all' to probe all HTTP methods")
	flag.BoolVar(&options.OutputMethod, "method", false, "Display request method")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&options.Version, "version", false, "Show version of httpx")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose Mode")
	flag.BoolVar(&options.NoColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&options.OutputServerHeader, "web-server", false, "Display server header")
	flag.BoolVar(&options.OutputWebSocket, "websocket", false, "Display server using websocket")
	flag.BoolVar(&options.responseInStdout, "response-in-json", false, "Show Raw HTTP response In Output (-json only) (deprecated)")
	flag.BoolVar(&options.responseInStdout, "include-response", false, "Show Raw HTTP response In Output (-json only)")
	flag.BoolVar(&options.chainInStdout, "include-chain", false, "Show Raw HTTP Chain In Output (-json only)")
	flag.BoolVar(&options.TLSProbe, "tls-probe", false, "Send HTTP probes on the extracted TLS domains")
	flag.BoolVar(&options.CSPProbe, "csp-probe", false, "Send HTTP probes on the extracted CSP domains")
	flag.StringVar(&options.RequestURI, "path", "", "Request path/file (example '/api')")
	flag.StringVar(&options.RequestURIs, "paths", "", "Command separated paths or file containing one path per line (example '/api/v1,/apiv2')")
	flag.BoolVar(&options.OutputContentType, "content-type", false, "Display content-type header")
	flag.StringVar(&options.OutputMatchStatusCode, "mc", "", "Match response with specific status code (-mc 200,302)")
	flag.StringVar(&options.OutputMatchContentLength, "ml", "", "Match response with specific content length (-ml 102)")
	flag.StringVar(&options.OutputFilterStatusCode, "fc", "", "Filter response with specific status code (-fc 403,401)")
	flag.StringVar(&options.OutputFilterContentLength, "fl", "", "Filter response with specific content length (-fl 23)")
	flag.StringVar(&options.InputRawRequest, "request", "", "File containing raw request")
	flag.BoolVar(&options.Unsafe, "unsafe", false, "Send raw requests skipping golang normalization")
	flag.StringVar(&options.RequestBody, "body", "", "Content to send in body with HTTP request")
	flag.BoolVar(&options.Debug, "debug", false, "Debug mode")
	flag.BoolVar(&options.Pipeline, "pipeline", false, "HTTP1.1 Pipeline probe")
	flag.BoolVar(&options.HTTP2Probe, "http2", false, "HTTP2 probe")
	flag.BoolVar(&options.OutputIP, "ip", false, "Display Host IP")
	flag.StringVar(&options.OutputFilterString, "filter-string", "", "Filter response with specific string")
	flag.StringVar(&options.OutputMatchString, "match-string", "", "Match response with specific string")
	flag.StringVar(&options.OutputFilterRegex, "filter-regex", "", "Filter response with specific regex")
	flag.StringVar(&options.OutputMatchRegex, "match-regex", "", "Match response with specific regex")
	flag.BoolVar(&options.OutputCName, "cname", false, "Display Host cname")
	flag.BoolVar(&options.OutputCDN, "cdn", false, "Display CDN")
	flag.BoolVar(&options.OutputResponseTime, "response-time", false, "Display the response time")
	flag.BoolVar(&options.NoFallback, "no-fallback", false, "Probe both protocol (HTTPS and HTTP)")
	flag.BoolVar(&options.NoFallbackScheme, "no-fallback-scheme", false, "Probe with input protocol scheme")
	flag.BoolVar(&options.ShowStatistics, "stats", false, "Enable statistic on keypress (terminal may become unresponsive till the end)")
	flag.BoolVar(&options.RandomAgent, "random-agent", true, "Use randomly selected HTTP User-Agent header value")
	flag.BoolVar(&options.StoreChain, "store-chain", false, "Save chain to file (default 'output')")
	flag.Var(&options.Allow, "allow", "Allow list of IP/CIDR's to process (file or comma separated)")
	flag.Var(&options.Deny, "deny", "Deny list of IP/CIDR's to process (file or comma separated)")
	flag.IntVar(&options.MaxResponseBodySizeToSave, "response-size-to-save", math.MaxInt32, "Max response size to save in bytes (default - unlimited)")
	flag.IntVar(&options.MaxResponseBodySizeToRead, "response-size-to-read", math.MaxInt32, "Max response size to read in bytes (default - unlimited)")
	flag.StringVar(&options.OutputExtractRegex, "extract-regex", "", "Display response content with matched regex")
	flag.IntVar(&options.RateLimit, "rate-limit", 150, "Maximum requests to send per second")
	flag.BoolVar(&options.Probe, "probe", false, "Display probe status")
	flag.BoolVar(&options.Resume, "resume", false, "Resume scan using resume.cfg")
	flag.BoolVar(&options.ExcludeCDN, "exclude-cdn", false, "Skip full port scans for CDNs (only checks for 80,443)")
	flag.IntVar(&options.HostMaxErrors, "max-host-error", 30, "Max error count per host before skipping remaining path/s")
	flag.BoolVar(&options.Stream, "stream", false, "Stream mode - start elaborating without sorting the input")
	flag.BoolVar(&options.SkipDedupe, "skip-dedupe", false, "Don't dedupe input items (only used with stream mode)")

	flag.Parse()

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.InputFile != "" && !fileutilz.FileNameIsGlob(options.InputFile) && !fileutil.FileExists(options.InputFile) {
		gologger.Fatal().Msgf("File %s does not exist.\n", options.InputFile)
	}

	if options.InputRawRequest != "" && !fileutil.FileExists(options.InputRawRequest) {
		gologger.Fatal().Msgf("File %s does not exist.\n", options.InputRawRequest)
	}

	multiOutput := options.CSVOutput && options.JSONOutput
	if multiOutput {
		gologger.Fatal().Msg("Results can only be displayed in one format: 'JSON' or 'CSV'\n")
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

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}
