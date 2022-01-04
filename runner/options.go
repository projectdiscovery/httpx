package runner

import (
	"math"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
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
	// The maximum file length is 251 (255 - 4 bytes for ".ext" suffix)
	maxFileNameLength      = 251
	two                    = 2
	DefaultResumeFile      = "resume.cfg"
	DefaultOutputDirectory = "output"
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
	ProbeAllIPS               bool
	Favicon                   bool
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputWordsCount          bool
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
		Favicon:                   s.Favicon,
		LeaveDefaultPorts:         s.LeaveDefaultPorts,
		OutputLinesCount:          s.OutputLinesCount,
		OutputWordsCount:          s.OutputWordsCount,
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
	DebugRequests             bool
	DebugResponse             bool
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
	ProbeAllIPS               bool
	Resolvers                 goflags.NormalizedStringSlice
	Favicon                   bool
	OutputFilterFavicon       goflags.NormalizedStringSlice
	OutputMatchFavicon        goflags.NormalizedStringSlice
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputMatchLinesCount     string
	matchLinesCount           []int
	OutputFilterLinesCount    string
	filterLinesCount          []int
	OutputWordsCount          bool
	OutputMatchWordsCount     string
	matchWordsCount           []int
	OutputFilterWordsCount    string
	filterWordsCount          []int
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using retryablehttp library.`)

	createGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "Input file containing list of hosts to process"),
		flagSet.StringVar(&options.InputRawRequest, "request", "", "File containing raw request"),
	)

	createGroup(flagSet, "Probes", "Probes",
		flagSet.BoolVarP(&options.StatusCode, "status-code", "sc", false, "Display Status Code"),
		flagSet.BoolVarP(&options.TechDetect, "tech-detect", "td", false, "Display wappalyzer based technology detection"),
		flagSet.BoolVarP(&options.ContentLength, "content-length", "cl", false, "Display Content-Length"),
		flagSet.BoolVarP(&options.OutputServerHeader, "web-server", "server", false, "Display Server header"),
		flagSet.BoolVarP(&options.OutputContentType, "content-type", "ct", false, "Display Content-Type header"),
		flagSet.BoolVarP(&options.OutputLinesCount, "line-count", "lc", false, "Display Response body line count"),
		flagSet.BoolVarP(&options.OutputWordsCount, "word-count", "wc", false, "Display Response body word count"),
		flagSet.BoolVarP(&options.OutputResponseTime, "response-time", "rt", false, "Display the response time"),
		flagSet.BoolVar(&options.ExtractTitle, "title", false, "Display page title"),
		flagSet.BoolVar(&options.Location, "location", false, "Display Location header"),
		flagSet.BoolVar(&options.OutputMethod, "method", false, "Display Request method"),
		flagSet.BoolVar(&options.OutputWebSocket, "websocket", false, "Display server using websocket"),
		flagSet.BoolVar(&options.OutputIP, "ip", false, "Display Host IP"),
		flagSet.BoolVar(&options.OutputCName, "cname", false, "Display Host cname"),
		flagSet.BoolVar(&options.OutputCDN, "cdn", false, "Display if CDN in use"),
		flagSet.BoolVar(&options.Probe, "probe", false, "Display probe status"),
	)

	createGroup(flagSet, "matchers", "Matchers",
		flagSet.StringVarP(&options.OutputMatchStatusCode, "match-code", "mc", "", "Match response with given status code (-mc 200,302)"),
		flagSet.StringVarP(&options.OutputMatchContentLength, "match-length", "ml", "", "Match response with given content length (-ml 100,102)"),
		flagSet.StringVarP(&options.OutputMatchString, "match-string", "ms", "", "Match response with given string"),
		flagSet.StringVarP(&options.OutputMatchRegex, "match-regex", "mr", "", "Match response with specific regex"),
		flagSet.StringVarP(&options.OutputExtractRegex, "extract-regex", "er", "", "Display response content with matched regex"),
		flagSet.StringVarP(&options.OutputMatchLinesCount, "match-line-count", "mlc", "", "Match Response body line count"),
		flagSet.StringVarP(&options.OutputMatchWordsCount, "match-word-count", "mwc", "", "Match Response body word count"),
		flagSet.NormalizedStringSliceVarP(&options.OutputMatchFavicon, "match-favicon", "mfc", []string{}, "Match response with specific favicon"),
	)

	createGroup(flagSet, "filters", "Filters",
		flagSet.StringVarP(&options.OutputFilterStatusCode, "filter-code", "fc", "", "Filter response with given status code (-fc 403,401)"),
		flagSet.StringVarP(&options.OutputFilterContentLength, "filter-length", "fl", "", "Filter response with given content length (-fl 23,33)"),
		flagSet.StringVarP(&options.OutputFilterString, "filter-string", "fs", "", "Filter response with specific string"),
		flagSet.StringVarP(&options.OutputFilterRegex, "filter-regex", "fe", "", "Filter response with specific regex"),
		flagSet.StringVarP(&options.OutputFilterLinesCount, "filter-line-count", "flc", "", "Filter Response body line count"),
		flagSet.StringVarP(&options.OutputFilterWordsCount, "filter-word-count", "fwc", "", "Filter Response body word count"),
		flagSet.NormalizedStringSliceVarP(&options.OutputFilterFavicon, "filter-favicon", "ffc", []string{}, "Filter response with specific favicon"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVarP(&options.Threads, "threads", "t", 50, "Number of threads"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "Maximum requests to send per second"),
	)

	createGroup(flagSet, "Misc", "Miscellaneous",
		flagSet.BoolVar(&options.Favicon, "favicon", false, "Probes for favicon (\"favicon.ico\" as path) and display phythonic hash"),
		flagSet.BoolVar(&options.TLSGrab, "tls-grab", false, "Perform TLS(SSL) data grabbing"),
		flagSet.BoolVar(&options.TLSProbe, "tls-probe", false, "Send HTTP probes on the extracted TLS domains"),
		flagSet.BoolVar(&options.CSPProbe, "csp-probe", false, "Send HTTP probes on the extracted CSP domains"),
		flagSet.BoolVar(&options.Pipeline, "pipeline", false, "HTTP1.1 Pipeline probe"),
		flagSet.BoolVar(&options.HTTP2Probe, "http2", false, "HTTP2 probe"),
		flagSet.BoolVar(&options.VHost, "vhost", false, "VHOST Probe"),
		flagSet.VarP(&options.CustomPorts, "ports", "p", "Port to scan (nmap syntax: eg 1,2-10,11)"),
		flagSet.StringVar(&options.RequestURIs, "path", "", "File or comma separated paths to request"),
		flagSet.StringVar(&options.RequestURIs, "paths", "", "File or comma separated paths to request (deprecated)"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output results"),
		flagSet.BoolVarP(&options.StoreResponse, "store-response", "sr", false, "store http response to output directory"),
		flagSet.StringVarP(&options.StoreResponseDir, "store-response-dir", "srd", "", "store http response to custom directory"),
		flagSet.BoolVar(&options.CSVOutput, "csv", false, "store output in CSV format"),
		flagSet.BoolVar(&options.JSONOutput, "json", false, "store output in JSONL(ines) format"),
		flagSet.BoolVarP(&options.responseInStdout, "include-response", "irr", false, "include http request/response in JSON output (-json only)"),
		flagSet.BoolVar(&options.chainInStdout, "include-chain", false, "include redirect http chain in JSON output (-json only)"),
		flagSet.BoolVar(&options.StoreChain, "store-chain", false, "include http redirect chain in responses (-sr only)"),
	)

	createGroup(flagSet, "configs", "Configurations",
		flagSet.NormalizedStringSliceVarP(&options.Resolvers, "resolvers", "r", []string{}, "List of custom resolvers (file or comma separated)"),
		flagSet.Var(&options.Allow, "allow", "Allowed list of IP/CIDR's to process (file or comma separated)"),
		flagSet.Var(&options.Deny, "deny", "Denied list of IP/CIDR's to process (file or comma separated)"),
		flagSet.BoolVar(&options.RandomAgent, "random-agent", true, "Enable Random User-Agent to use"),
		flagSet.VarP(&options.CustomHeaders, "header", "H", "Custom Header to send with request"),
		flagSet.StringVarP(&options.HTTPProxy, "proxy", "http-proxy", "", "HTTP Proxy, eg http://127.0.0.1:8080"),
		flagSet.BoolVar(&options.Unsafe, "unsafe", false, "Send raw requests skipping golang normalization"),
		flagSet.BoolVar(&options.Resume, "resume", false, "Resume scan using resume.cfg"),
		flagSet.BoolVarP(&options.FollowRedirects, "follow-redirects", "fr", false, "Follow HTTP redirects"),
		flagSet.IntVarP(&options.MaxRedirects, "max-redirects", "maxr", 10, "Max number of redirects to follow per host"),
		flagSet.BoolVarP(&options.FollowHostRedirects, "follow-host-redirects", "fhr", false, "Follow redirects on the same host"),
		flagSet.BoolVar(&options.VHostInput, "vhost-input", false, "Get a list of vhosts as input"),
		flagSet.StringVar(&options.Methods, "x", "", "Request methods to use, use 'all' to probe all HTTP methods"),
		flagSet.StringVar(&options.RequestBody, "body", "", "Post body to include in HTTP request"),
		flagSet.BoolVarP(&options.Stream, "stream", "s", false, "Stream mode - start elaborating input targets without sorting"),
		flagSet.BoolVarP(&options.SkipDedupe, "skip-dedupe", "sd", false, "Disable dedupe input items (only used with stream mode)"),
		flagSet.BoolVarP(&options.ProbeAllIPS, "probe-all-ips", "pa", false, "Probe all the ips associated with same host"),
		flagSet.BoolVarP(&options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "Leave default HTTP/HTTPS ports (eg. http://host:80 - https//host:443"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "Silent mode"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "Verbose mode"),
		flagSet.BoolVar(&options.Version, "version", false, "Display version"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "Disable color in output"),
		flagSet.BoolVar(&options.Debug, "debug", false, "Debug mode"),
		flagSet.BoolVar(&options.DebugRequests, "debug-req", false, "Show all sent requests"),
		flagSet.BoolVar(&options.DebugResponse, "debug-resp", false, "Show all received responses"),
		flagSet.BoolVar(&options.ShowStatistics, "stats", false, "Display scan statistic"),
	)

	createGroup(flagSet, "Optimizations", "Optimizations",
		flagSet.BoolVarP(&options.NoFallback, "no-fallback", "nf", false, "Display both probbed protocol (HTTPS and HTTP)"),
		flagSet.BoolVarP(&options.NoFallbackScheme, "no-fallback-scheme", "nfs", false, "Probe with input protocol scheme"),
		flagSet.IntVarP(&options.HostMaxErrors, "max-host-error", "maxhr", 30, "Max error count per host before skipping remaining path/s"),
		flagSet.BoolVarP(&options.ExcludeCDN, "exclude-cdn", "ec", false, "Skip full port scans for CDNs (only checks for 80,443)"),
		flagSet.IntVar(&options.Retries, "retries", 0, "Number of retries"),
		flagSet.IntVar(&options.Timeout, "timeout", 5, "Timeout in seconds"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToSave, "response-size-to-save", "rsts", math.MaxInt32, "Max response size to save in bytes"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToRead, "response-size-to-read", "rstr", math.MaxInt32, "Max response size to read in bytes"),
	)

	_ = flagSet.Parse()
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
	if options.matchLinesCount, err = stringz.StringToSliceInt(options.OutputMatchLinesCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for match lines count option: %s\n", err)
	}
	if options.matchWordsCount, err = stringz.StringToSliceInt(options.OutputMatchWordsCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for match words count option: %s\n", err)
	}
	if options.filterLinesCount, err = stringz.StringToSliceInt(options.OutputFilterLinesCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter lines count option: %s\n", err)
	}
	if options.filterWordsCount, err = stringz.StringToSliceInt(options.OutputFilterWordsCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter words count option: %s\n", err)
	}

	var resolvers []string
	for _, resolver := range options.Resolvers {
		if fileutil.FileExists(resolver) {
			chFile, err := fileutil.ReadFile(resolver)
			if err != nil {
				gologger.Fatal().Msgf("Couldn't process resolver file \"%s\": %s\n", resolver, err)
			}
			for line := range chFile {
				resolvers = append(resolvers, line)
			}
		} else {
			resolvers = append(resolvers, resolver)
		}
	}
	options.Resolvers = resolvers
	if len(options.Resolvers) > 0 {
		gologger.Debug().Msgf("Using resolvers: %s\n", strings.Join(options.Resolvers, ","))
	}

	if options.StoreResponse && options.StoreResponseDir == "" {
		gologger.Debug().Msgf("Store response directory not specified, using \"%s\"\n", DefaultOutputDirectory)
		options.StoreResponseDir = DefaultOutputDirectory
	}
	if options.StoreResponseDir != "" && !options.StoreResponse {
		gologger.Debug().Msgf("Store response directory specified, enabling \"sr\" flag automatically\n")
		options.StoreResponse = true
	}

	if options.Favicon {
		gologger.Debug().Msgf("Setting single path to \"favicon.ico\" and ignoring multiple paths settings\n")
		options.RequestURIs = "/favicon.ico"
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

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
