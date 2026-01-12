package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	"github.com/PuerkitoBio/goquery"
	"github.com/corona10/goimagehash"
	"github.com/gocarina/gocsv"
	"github.com/mfonda/simhash"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/httpx/common/customextract"
	"github.com/projectdiscovery/httpx/common/hashes/jarm"
	"github.com/projectdiscovery/httpx/common/inputformats"
	"github.com/projectdiscovery/httpx/common/pagetypeclassifier"
	"github.com/projectdiscovery/httpx/common/authprovider"
	"github.com/projectdiscovery/httpx/static"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/networkpolicy"
	osutil "github.com/projectdiscovery/utils/os"
	"github.com/projectdiscovery/utils/structs"

	"github.com/Mzack9999/gcache"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/httpx/common/hashes"
	"github.com/projectdiscovery/retryablehttp-go"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"

	"github.com/projectdiscovery/ratelimit"

	// automatic fd max increase if running as root
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	customport "github.com/projectdiscovery/httpx/common/customports"
	fileutilz "github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/httputilz"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/stringz"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/rawhttp"
	converstionutil "github.com/projectdiscovery/utils/conversion"
	errkit "github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	pdhttputil "github.com/projectdiscovery/utils/http"
	iputil "github.com/projectdiscovery/utils/ip"
	syncutil "github.com/projectdiscovery/utils/sync"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	options            *Options
	hp                 *httpx.HTTPX
	wappalyzer         *wappalyzer.Wappalyze
	cpeDetector        *CPEDetector
	wpDetector         *WordPressDetector
	scanopts           ScanOptions
	hm                 *hybrid.HybridMap
	excludeCdn         bool
	stats              clistats.StatisticsClient
	ratelimiter        ratelimit.Limiter
	HostErrorsCache    gcache.Cache[string, int]
	browser            *Browser
	pageTypeClassifier *pagetypeclassifier.PageTypeClassifier // Include this for general page classification
	pHashClusters      []pHashCluster
	simHashes          gcache.Cache[uint64, struct{}] // Include simHashes for efficient duplicate detection
	httpApiEndpoint    *Server
	authProvider       authprovider.AuthProvider
}

func (r *Runner) HTTPX() *httpx.HTTPX {
	return r.hp
}

// picked based on try-fail but it seems to close to one it's used https://www.hackerfactor.com/blog/index.php?/archives/432-Looks-Like-It.html#c1992
var hammingDistanceThreshold int = 22

// regex for stripping ANSI codes
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type pHashCluster struct {
	BasePHash uint64     `json:"base_phash,omitempty" csv:"base_phash"`
	Hashes    []pHashUrl `json:"hashes,omitempty" csv:"hashes"`
}
type pHashUrl struct {
	PHash uint64 `json:"phash,omitempty" csv:"phash"`
	Url   string `json:"url,omitempty" csv:"url"`
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	var err error
	if options.Wappalyzer != nil {
		runner.wappalyzer = options.Wappalyzer
	} else if options.TechDetect || options.JSONOutput || options.CSVOutput || options.AssetUpload {
		runner.wappalyzer, err = func() (*wappalyzer.Wappalyze, error) {
			if options.CustomFingerprintFile != "" {
				return wappalyzer.NewFromFile(options.CustomFingerprintFile, true, true)
			}
			return wappalyzer.New()
		}()
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create wappalyzer client")
	}

	if options.CPEDetect || options.JSONOutput || options.CSVOutput {
		runner.cpeDetector, err = NewCPEDetector()
		if err != nil {
			gologger.Warning().Msgf("Could not create CPE detector: %s", err)
		}
	}

	if options.WordPress || options.JSONOutput || options.CSVOutput {
		runner.wpDetector, err = NewWordPressDetector()
		if err != nil {
			gologger.Warning().Msgf("Could not create WordPress detector: %s", err)
		}
	}

	if options.StoreResponseDir != "" {
		// Don't remove index files if skip-dedupe is enabled (we want to append, not truncate)
		if !options.SkipDedupe {
			_ = os.RemoveAll(filepath.Join(options.StoreResponseDir, "response", "index.txt"))
			_ = os.RemoveAll(filepath.Join(options.StoreResponseDir, "screenshot", "index_screenshot.txt"))
		}
	}

	httpxOptions := httpx.DefaultOptions
	httpxOptions.Trace = options.Trace

	var np *networkpolicy.NetworkPolicy
	if options.Networkpolicy != nil {
		np = options.Networkpolicy
	} else {
		np, err = runner.createNetworkpolicyInstance(options)
	}
	if err != nil {
		return nil, err
	}
	httpxOptions.NetworkPolicy = np
	httpxOptions.CDNCheckClient = options.CDNCheckClient

	// Enables automatically tlsgrab if tlsprobe is requested
	httpxOptions.TLSGrab = options.TLSGrab || options.TLSProbe
	httpxOptions.Timeout = time.Duration(options.Timeout) * time.Second
	httpxOptions.RetryMax = options.Retries
	httpxOptions.FollowRedirects = options.FollowRedirects
	httpxOptions.FollowHostRedirects = options.FollowHostRedirects
	httpxOptions.RespectHSTS = options.RespectHSTS
	httpxOptions.MaxRedirects = options.MaxRedirects
	if options.HTTPProxy != "" {
		options.Proxy = options.HTTPProxy
	} else if options.SocksProxy != "" {
		options.Proxy = options.SocksProxy
	}
	httpxOptions.Proxy = options.Proxy
	httpxOptions.Unsafe = options.Unsafe
	httpxOptions.UnsafeURI = options.RequestURI
	httpxOptions.CdnCheck = options.OutputCDN
	httpxOptions.ExcludeCdn = runner.excludeCdn
	httpxOptions.ExtractFqdn = options.ExtractFqdn
	if options.CustomHeaders.Has("User-Agent:") {
		httpxOptions.RandomAgent = false
	} else {
		httpxOptions.RandomAgent = options.RandomAgent
	}
	if options.CustomHeaders.Has("Referer:") {
		httpxOptions.AutoReferer = false
	} else {
		httpxOptions.AutoReferer = options.AutoReferer
	}
	httpxOptions.ZTLS = options.ZTLS
	httpxOptions.MaxResponseBodySizeToSave = int64(options.MaxResponseBodySizeToSave)
	httpxOptions.MaxResponseBodySizeToRead = int64(options.MaxResponseBodySizeToRead)
	// adjust response size saved according to the max one read by the server
	if httpxOptions.MaxResponseBodySizeToSave > httpxOptions.MaxResponseBodySizeToRead {
		httpxOptions.MaxResponseBodySizeToSave = httpxOptions.MaxResponseBodySizeToRead
	}
	httpxOptions.Resolvers = options.Resolvers
	httpxOptions.TlsImpersonate = options.TlsImpersonate
	httpxOptions.Protocol = httpx.Proto(options.Protocol)

	var key, value string
	httpxOptions.CustomHeaders = make(map[string]string)
	for _, customHeader := range options.CustomHeaders {
		tokens := strings.SplitN(customHeader, ":", two)
		// rawhttp skips all checks
		if options.Unsafe {
			httpxOptions.CustomHeaders[customHeader] = ""
			continue
		}

		// Continue normally
		if len(tokens) < two {
			continue
		}
		key = strings.TrimSpace(tokens[0])
		value = strings.TrimSpace(tokens[1])
		httpxOptions.CustomHeaders[key] = value
	}
	httpxOptions.SniName = options.SniName

	runner.hp, err = httpx.New(&httpxOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create httpx instance: %s\n", err)
	}

	var scanopts ScanOptions

	if options.InputRawRequest != "" {
		var rawRequest []byte
		rawRequest, err = os.ReadFile(options.InputRawRequest)
		if err != nil {
			gologger.Fatal().Msgf("Could not read raw request from path '%s': %s\n", options.InputRawRequest, err)
		}

		rrMethod, rrPath, rrHeaders, rrBody, errParse := httputilz.ParseRequest(string(rawRequest), options.Unsafe)
		if errParse != nil {
			gologger.Fatal().Msgf("Could not parse raw request: %s\n", err)
		}
		scanopts.Methods = append(scanopts.Methods, rrMethod)
		scanopts.RequestURI = rrPath
		for name, value := range rrHeaders {
			httpxOptions.CustomHeaders[name] = value
		}
		scanopts.RequestBody = rrBody
		options.rawRequest = string(rawRequest)
		options.RequestBody = rrBody
	}

	// disable automatic host header for rawhttp if manually specified
	// as it can be malformed the best approach is to remove spaces and check for lowercase "host" word
	if options.Unsafe {
		for name := range runner.hp.CustomHeaders {
			nameLower := strings.TrimSpace(strings.ToLower(name))
			if strings.HasPrefix(nameLower, "host") {
				rawhttp.AutomaticHostHeader(false)
			}
		}
	}
	if strings.EqualFold(options.Methods, "all") {
		scanopts.Methods = pdhttputil.AllHTTPMethods()
	} else if options.Methods != "" {
		// if unsafe is specified then converts the methods to uppercase
		if !options.Unsafe {
			options.Methods = strings.ToUpper(options.Methods)
		}
		scanopts.Methods = append(scanopts.Methods, stringz.SplitByCharAndTrimSpace(options.Methods, ",")...)
	}
	if len(scanopts.Methods) == 0 {
		scanopts.Methods = append(scanopts.Methods, http.MethodGet)
	}
	runner.options.protocol = httpx.HTTPorHTTPS
	scanopts.VHost = options.VHost
	scanopts.OutputTitle = options.ExtractTitle
	scanopts.OutputStatusCode = options.StatusCode
	scanopts.OutputLocation = options.Location
	scanopts.OutputContentLength = options.ContentLength
	scanopts.StoreResponse = options.StoreResponse
	scanopts.StoreResponseDirectory = options.StoreResponseDir
	scanopts.OutputServerHeader = options.OutputServerHeader
	scanopts.ResponseHeadersInStdout = options.ResponseHeadersInStdout
	scanopts.OutputWithNoColor = options.NoColor
	scanopts.ResponseInStdout = options.ResponseInStdout
	scanopts.Base64ResponseInStdout = options.Base64ResponseInStdout
	scanopts.ChainInStdout = options.ChainInStdout
	scanopts.OutputWebSocket = options.OutputWebSocket
	scanopts.TLSProbe = options.TLSProbe
	scanopts.CSPProbe = options.CSPProbe
	if options.RequestURI != "" {
		scanopts.RequestURI = options.RequestURI
	}
	scanopts.VHostInput = options.VHostInput
	scanopts.OutputContentType = options.OutputContentType
	scanopts.RequestBody = options.RequestBody
	scanopts.Unsafe = options.Unsafe
	scanopts.Pipeline = options.Pipeline
	scanopts.HTTP2Probe = options.HTTP2Probe
	scanopts.OutputMethod = options.OutputMethod
	scanopts.OutputIP = options.OutputIP
	scanopts.OutputCName = options.OutputCName
	scanopts.OutputCDN = options.OutputCDN
	scanopts.OutputResponseTime = options.OutputResponseTime
	scanopts.NoFallback = options.NoFallback
	scanopts.NoFallbackScheme = options.NoFallbackScheme
	scanopts.TechDetect = options.TechDetect || options.JSONOutput || options.CSVOutput || options.AssetUpload
	scanopts.CPEDetect = options.CPEDetect || options.JSONOutput || options.CSVOutput
	scanopts.WordPress = options.WordPress || options.JSONOutput || options.CSVOutput
	scanopts.StoreChain = options.StoreChain
	scanopts.StoreVisionReconClusters = options.StoreVisionReconClusters
	scanopts.MaxResponseBodySizeToSave = options.MaxResponseBodySizeToSave
	scanopts.MaxResponseBodySizeToRead = options.MaxResponseBodySizeToRead
	scanopts.extractRegexps = make(map[string]*regexp.Regexp)
	if options.Screenshot {
		browser, err := NewBrowser(options.HTTPProxy, options.UseInstalledChrome, options.ParseHeadlessOptionalArguments())
		if err != nil {
			return nil, err
		}
		runner.browser = browser
	}
	scanopts.Screenshot = options.Screenshot
	scanopts.NoScreenshotBytes = options.NoScreenshotBytes
	scanopts.NoHeadlessBody = options.NoHeadlessBody
	scanopts.NoScreenshotFullPage = options.NoScreenshotFullPage
	scanopts.UseInstalledChrome = options.UseInstalledChrome
	scanopts.ScreenshotTimeout = options.ScreenshotTimeout
	scanopts.ScreenshotIdle = options.ScreenshotIdle

	if options.OutputExtractRegexs != nil {
		for _, regex := range options.OutputExtractRegexs {
			if compiledRegex, err := regexp.Compile(regex); err != nil {
				return nil, err
			} else {
				scanopts.extractRegexps[regex] = compiledRegex
			}
		}
	}

	if options.OutputExtractPresets != nil {
		for _, regexName := range options.OutputExtractPresets {
			if regex, ok := customextract.ExtractPresets[regexName]; ok {
				scanopts.extractRegexps[regexName] = regex
			} else {
				availablePresets := strings.Join(maps.Keys(customextract.ExtractPresets), ",")
				gologger.Warning().Msgf("Could not find preset: '%s'. Available presets are: %s\n", regexName, availablePresets)
			}
		}
	}

	// output verb if more than one is specified
	if len(scanopts.Methods) > 1 && !options.Silent {
		scanopts.OutputMethod = true
	}

	scanopts.ExcludeCDN = runner.excludeCdn
	scanopts.HostMaxErrors = options.HostMaxErrors
	scanopts.ProbeAllIPS = options.ProbeAllIPS
	scanopts.Favicon = options.Favicon
	scanopts.LeaveDefaultPorts = options.LeaveDefaultPorts
	scanopts.OutputLinesCount = options.OutputLinesCount
	scanopts.OutputWordsCount = options.OutputWordsCount
	scanopts.Hashes = options.Hashes
	runner.scanopts = scanopts

	if options.ShowStatistics {
		runner.stats, err = clistats.New()
		if err != nil {
			return nil, err
		}
		if options.StatsInterval == 0 {
			options.StatsInterval = 5
		}
	}

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}
	runner.hm = hm

	if options.RateLimitMinute > 0 {
		runner.ratelimiter = *ratelimit.New(context.Background(), uint(options.RateLimitMinute), time.Minute)
	} else if options.RateLimit > 0 {
		runner.ratelimiter = *ratelimit.New(context.Background(), uint(options.RateLimit), time.Second)
	} else {
		runner.ratelimiter = *ratelimit.NewUnlimited(context.Background())
	}

	if options.HostMaxErrors >= 0 {
		gc := gcache.New[string, int](1000).
			ARC().
			Build()
		runner.HostErrorsCache = gc
	}

	runner.simHashes = gcache.New[uint64, struct{}](1000).ARC().Build()
	pageTypeClassifier, err := pagetypeclassifier.New()
	if err != nil {
		return nil, err
	}
	runner.pageTypeClassifier = pageTypeClassifier

	if options.SecretFile != "" {
		authProviderOpts := &authprovider.AuthProviderOptions{
			SecretsFiles: []string{options.SecretFile},
		}
		runner.authProvider, err = authprovider.NewAuthProvider(authProviderOpts)
		if err != nil {
			return nil, errors.Wrap(err, "could not create auth provider")
		}
	}

	if options.HttpApiEndpoint != "" {
		apiServer := NewServer(options.HttpApiEndpoint, options)
		gologger.Info().Msgf("Listening api endpoint on: %s", options.HttpApiEndpoint)
		runner.httpApiEndpoint = apiServer
		go func() {
			if err := apiServer.Start(); err != nil {
				gologger.Error().Msgf("Failed to start API server: %s", err)
			}
		}()
	}

	return runner, nil
}

func (runner *Runner) createNetworkpolicyInstance(options *Options) (*networkpolicy.NetworkPolicy, error) {
	var npOptions networkpolicy.Options
	for _, exclude := range options.Exclude {
		switch {
		case exclude == "cdn":
			//implement cdn check in netoworkpolicy pkg??
			runner.excludeCdn = true
			continue
		case exclude == "private-ips":
			npOptions.DenyList = append(npOptions.DenyList, networkpolicy.DefaultIPv4Denylist...)
			npOptions.DenyList = append(npOptions.DenyList, networkpolicy.DefaultIPv4DenylistRanges...)
			npOptions.DenyList = append(npOptions.DenyList, networkpolicy.DefaultIPv6Denylist...)
			npOptions.DenyList = append(npOptions.DenyList, networkpolicy.DefaultIPv6DenylistRanges...)
		case iputil.IsCIDR(exclude):
			npOptions.DenyList = append(npOptions.DenyList, exclude)
		case asn.IsASN(exclude):
			// update this to use networkpolicy pkg once https://github.com/projectdiscovery/networkpolicy/pull/55 is merged
			ips := expandASNInputValue(exclude)
			npOptions.DenyList = append(npOptions.DenyList, ips...)
		case iputil.IsPort(exclude):
			port, _ := strconv.Atoi(exclude)
			npOptions.DenyPortList = append(npOptions.DenyPortList, port)
		default:
			npOptions.DenyList = append(npOptions.DenyList, exclude)
		}
	}

	npOptions.AllowList = appendToList(npOptions.AllowList, options.Allow...)
	npOptions.DenyList = appendToList(npOptions.DenyList, options.Deny...)

	np, err := networkpolicy.New(npOptions)
	return np, err
}

func appendToList(list []string, values ...string) []string {
	for _, value := range values {
		switch {
		case asn.IsASN(value):
			ips := expandASNInputValue(value)
			list = append(list, ips...)
		default:
			list = append(list, value)
		}
	}
	return list
}

func expandCIDRInputValue(value string) []string {
	var ips []string
	ipsCh, _ := mapcidr.IPAddressesAsStream(value)
	for ip := range ipsCh {
		ips = append(ips, ip)
	}
	return ips
}

func expandASNInputValue(value string) []string {
	var ips []string
	cidrs, _ := asn.GetCIDRsForASNNum(value)
	for _, cidr := range cidrs {
		ips = append(ips, expandCIDRInputValue(cidr.String())...)
	}
	return ips
}

func (r *Runner) prepareInputPaths() {
	// most likely, the user would provide the most simplified path to an existing file
	isAbsoluteOrRelativePath := filepath.Clean(r.options.RequestURIs) == r.options.RequestURIs
	// Check if the user requested multiple paths
	if isAbsoluteOrRelativePath && fileutil.FileExists(r.options.RequestURIs) {
		r.options.requestURIs = fileutilz.LoadFile(r.options.RequestURIs)
	} else if r.options.RequestURIs != "" {
		r.options.requestURIs = strings.Split(r.options.RequestURIs, ",")
	}
}

var duplicateTargetErr = errors.New("duplicate target")

func (r *Runner) prepareInput() {
	var numHosts int
	// check if input target host(s) have been provided
	if len(r.options.InputTargetHost) > 0 {
		for _, target := range r.options.InputTargetHost {
			expandedTarget, err := r.countTargetFromRawTarget(target)
			if err == nil && expandedTarget > 0 {
				numHosts += expandedTarget
				r.hm.Set(target, []byte("1")) //nolint
			} else if r.options.SkipDedupe && errors.Is(err, duplicateTargetErr) {
				if v, ok := r.hm.Get(target); ok {
					cnt, _ := strconv.Atoi(string(v))
					_ = r.hm.Set(target, []byte(strconv.Itoa(cnt+1)))
					numHosts += 1
				}
			}
		}
	}
	// check if file has been provided
	if fileutil.FileExists(r.options.InputFile) {
		// check if input mode is specified for special format handling
		if format := r.getInputFormat(); format != nil {
			numTargets, err := r.loadFromFormat(r.options.InputFile, format)
			if err != nil {
				gologger.Fatal().Msgf("Could not parse input file '%s': %s\n", r.options.InputFile, err)
			}
			numHosts = numTargets
		} else {
			finput, err := os.Open(r.options.InputFile)
			if err != nil {
				gologger.Fatal().Msgf("Could not read input file '%s': %s\n", r.options.InputFile, err)
			}
			numHosts, err = r.loadAndCloseFile(finput)
			if err != nil {
				gologger.Fatal().Msgf("Could not read input file '%s': %s\n", r.options.InputFile, err)
			}
		}
	} else if r.options.InputFile != "" {
		files, err := fileutilz.ListFilesWithPattern(r.options.InputFile)
		if err != nil {
			gologger.Fatal().Msgf("No input provided: %s", err)
		}
		for _, file := range files {
			finput, err := os.Open(file)
			if err != nil {
				gologger.Fatal().Msgf("Could not read input file '%s': %s\n", r.options.InputFile, err)
			}
			numTargetsFile, err := r.loadAndCloseFile(finput)
			if err != nil {
				gologger.Fatal().Msgf("Could not read input file '%s': %s\n", r.options.InputFile, err)
			}
			numHosts += numTargetsFile
		}
	}
	if !r.options.DisableStdin && fileutil.HasStdin() {
		numTargetsStdin, err := r.loadAndCloseFile(os.Stdin)
		if err != nil {
			gologger.Fatal().Msgf("Could not read input from stdin: %s\n", err)
		}
		numHosts += numTargetsStdin
	}

	// Adjust total hosts based on the number of paths
	if len(r.options.requestURIs) > 0 {
		numHosts *= len(r.options.requestURIs)
	}

	if r.options.ShowStatistics {
		r.stats.AddStatic("totalHosts", numHosts)
		r.stats.AddCounter("hosts", 0)
		r.stats.AddStatic("startedAt", time.Now())
		r.stats.AddCounter("requests", 0)
		r.stats.AddDynamic("summary", makePrintCallback())
		err := r.stats.Start()
		if err != nil {
			gologger.Warning().Msgf("Could not create statistics: %s\n", err)
		}

		r.stats.GetStatResponse(time.Duration(r.options.StatsInterval)*time.Second, func(s string, err error) error {
			if err != nil && r.options.Verbose {
				gologger.Error().Msgf("Could not read statistics: %s\n", err)
			}
			return nil
		})
	}
}

func (r *Runner) setSeen(k string) {
	_ = r.hm.Set(k, nil)
}

func (r *Runner) seen(k string) bool {
	_, ok := r.hm.Get(k)
	return ok
}

func (r *Runner) duplicate(result *Result) bool {
	respSimHash := simhash.Simhash(simhash.NewWordFeatureSet(converstionutil.Bytes(result.Raw)))
	if r.simHashes.Has(respSimHash) {
		gologger.Debug().Msgf("Skipping duplicate response with simhash %d for URL %s\n", respSimHash, result.URL)
		return true
	}

	for simHash := range r.simHashes.GetALL(false) {
		// lower threshold for increased precision
		if simhash.Compare(simHash, respSimHash) <= 3 {
			gologger.Debug().Msgf("Skipping near-duplicate response with simhash %d for URL %s\n", respSimHash, result.URL)
			return true
		}
	}
	_ = r.simHashes.Set(respSimHash, struct{}{})
	return false
}

func (r *Runner) testAndSet(k string) bool {
	// skip empty lines
	k = strings.TrimSpace(k)
	if k == "" {
		return false
	}

	if r.seen(k) {
		return false
	}

	r.setSeen(k)
	return true
}

// getInputFormat returns the format for the configured input mode.
// Returns nil if no input mode is configured, or logs fatal if the format is invalid.
func (r *Runner) getInputFormat() inputformats.Format {
	if r.options.InputMode == "" {
		return nil
	}
	format := inputformats.GetFormat(r.options.InputMode)
	if format == nil {
		gologger.Fatal().Msgf("Invalid input mode '%s'. Supported: %s\n", r.options.InputMode, inputformats.SupportedFormats())
	}
	return format
}

func (r *Runner) streamInput() (chan string, error) {
	out := make(chan string)
	go func() {
		defer close(out)

		if fileutil.FileExists(r.options.InputFile) {
			// check if input mode is specified for special format handling
			if format := r.getInputFormat(); format != nil {
				finput, err := os.Open(r.options.InputFile)
				if err != nil {
					gologger.Error().Msgf("Could not open input file '%s': %s\n", r.options.InputFile, err)
					return
				}
				defer finput.Close()
				if err := format.Parse(finput, func(item string) bool {
					item = strings.TrimSpace(item)
					if r.options.SkipDedupe || r.testAndSet(item) {
						out <- item
					}
					return true
				}); err != nil {
					gologger.Error().Msgf("Could not parse input file '%s': %s\n", r.options.InputFile, err)
					return
				}
			} else {
				fchan, err := fileutil.ReadFile(r.options.InputFile)
				if err != nil {
					return
				}
				for item := range fchan {
					if r.options.SkipDedupe || r.testAndSet(item) {
						out <- item
					}
				}
			}
		} else if r.options.InputFile != "" {
			files, err := fileutilz.ListFilesWithPattern(r.options.InputFile)
			if err != nil {
				gologger.Fatal().Msgf("No input provided: %s", err)
			}
			for _, file := range files {
				fchan, err := fileutil.ReadFile(file)
				if err != nil {
					return
				}
				for item := range fchan {
					if r.options.SkipDedupe || r.testAndSet(item) {
						out <- item
					}
				}
			}
		}
		if fileutil.HasStdin() {
			fchan, err := fileutil.ReadFileWithReader(os.Stdin)
			if err != nil {
				return
			}
			for item := range fchan {
				if r.options.SkipDedupe || r.testAndSet(item) {
					out <- item
				}
			}
		}
	}()
	return out, nil
}

func (r *Runner) loadAndCloseFile(finput *os.File) (numTargets int, err error) {
	scanner := bufio.NewScanner(finput)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		// Used just to get the exact number of targets
		expandedTarget, err := r.countTargetFromRawTarget(target)
		if err == nil && expandedTarget > 0 {
			numTargets += expandedTarget
			r.hm.Set(target, []byte("1")) //nolint
		} else if r.options.SkipDedupe && errors.Is(err, duplicateTargetErr) {
			if v, ok := r.hm.Get(target); ok {
				cnt, _ := strconv.Atoi(string(v))
				_ = r.hm.Set(target, []byte(strconv.Itoa(cnt+1)))
				numTargets += 1
			}
		}
	}
	err = finput.Close()
	return numTargets, err
}

func (r *Runner) loadFromFormat(filePath string, format inputformats.Format) (numTargets int, err error) {
	finput, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer finput.Close()

	err = format.Parse(finput, func(target string) bool {
		target = strings.TrimSpace(target)
		expandedTarget, countErr := r.countTargetFromRawTarget(target)
		if countErr == nil && expandedTarget > 0 {
			numTargets += expandedTarget
			r.hm.Set(target, []byte("1")) //nolint
		} else if r.options.SkipDedupe && errors.Is(countErr, duplicateTargetErr) {
			if v, ok := r.hm.Get(target); ok {
				cnt, _ := strconv.Atoi(string(v))
				_ = r.hm.Set(target, []byte(strconv.Itoa(cnt+1)))
				numTargets += 1
			}
		}
		return true
	})
	return numTargets, err
}

func (r *Runner) countTargetFromRawTarget(rawTarget string) (numTargets int, err error) {
	if rawTarget == "" {
		return 0, nil
	}

	if _, ok := r.hm.Get(rawTarget); ok {
		return 0, duplicateTargetErr
	}

	expandedTarget := 0
	switch {
	case iputil.IsCIDR(rawTarget):
		if ipsCount, err := mapcidr.AddressCount(rawTarget); err == nil && ipsCount > 0 {
			expandedTarget = int(ipsCount)
		}
	case asn.IsASN(rawTarget):
		cidrs, err := asn.GetCIDRsForASNNum(rawTarget)
		if err != nil {
			return 0, err
		}
		for _, cidr := range cidrs {
			expandedTarget += int(mapcidr.AddressCountIpnet(cidr))
		}
	default:
		expandedTarget = 1
	}
	return expandedTarget, nil
}

var (
	lastRequestsCount float64
)

func makePrintCallback() func(stats clistats.StatisticsClient) interface{} {
	builder := &strings.Builder{}
	return func(stats clistats.StatisticsClient) interface{} {
		startedAt, _ := stats.GetStatic("startedAt")
		duration := time.Since(startedAt.(time.Time))

		builder.WriteRune('[')
		builder.WriteString(clistats.FmtDuration(duration))
		builder.WriteRune(']')

		var currentRequests float64
		if reqs, _ := stats.GetCounter("requests"); reqs > 0 {
			currentRequests = float64(reqs)
		}

		builder.WriteString(" | RPS: ")
		incrementRequests := currentRequests - lastRequestsCount
		builder.WriteString(clistats.String(uint64(incrementRequests / duration.Seconds())))

		builder.WriteString(" | Requests: ")
		_, _ = fmt.Fprintf(builder, "%.0f", currentRequests)

		hosts, _ := stats.GetCounter("hosts")
		totalHosts, _ := stats.GetStatic("totalHosts")

		builder.WriteString(" | Hosts: ")
		builder.WriteString(clistats.String(hosts))
		builder.WriteRune('/')
		builder.WriteString(clistats.String(totalHosts))
		builder.WriteRune(' ')
		builder.WriteRune('(')
		builder.WriteString(clistats.String(uint64(float64(hosts) / float64(totalHosts.(int)) * 100.0)))
		builder.WriteRune('%')
		builder.WriteRune(')')

		builder.WriteRune('\n')
		statString := builder.String()
		fmt.Fprintf(os.Stderr, "%s", statString)
		builder.Reset()

		lastRequestsCount = currentRequests
		return statString
	}
}

// Close closes the httpx scan instance
func (r *Runner) Close() {
	// nolint:errcheck // ignore
	r.hm.Close()
	r.hp.Dialer.Close()
	r.ratelimiter.Stop()

	if r.options.HostMaxErrors >= 0 {
		r.HostErrorsCache.Purge()
	}
	if r.options.Screenshot {
		r.browser.Close()
	}
	if r.options.ShowStatistics {
		_ = r.stats.Stop()
	}
	if r.options.HttpApiEndpoint != "" {
		_ = r.httpApiEndpoint.Stop()
	}
	if r.options.OnClose != nil {
		r.options.OnClose()
	}
}

// RunEnumeration on targets for httpx client
func (r *Runner) RunEnumeration() {
	// Try to create output folders if it doesn't exist
	if r.options.StoreResponse && !fileutil.FolderExists(r.options.StoreResponseDir) {
		// main folder
		if err := os.MkdirAll(r.options.StoreResponseDir, os.ModePerm); err != nil {
			gologger.Fatal().Msgf("Could not create output directory '%s': %s\n", r.options.StoreResponseDir, err)
		}
		// response folder
		responseFolder := filepath.Join(r.options.StoreResponseDir, "response")
		if err := os.MkdirAll(responseFolder, os.ModePerm); err != nil {
			gologger.Fatal().Msgf("Could not create output response directory '%s': %s\n", r.options.StoreResponseDir, err)
		}
	}

	// screenshot folder
	if r.options.Screenshot {
		screenshotFolder := filepath.Join(r.options.StoreResponseDir, "screenshot")
		if err := os.MkdirAll(screenshotFolder, os.ModePerm); err != nil {
			gologger.Fatal().Msgf("Could not create output screenshot directory '%s': %s\n", r.options.StoreResponseDir, err)
		}
	}

	r.prepareInputPaths()

	var streamChan chan string
	if r.options.Stream {
		var err error
		streamChan, err = r.streamInput()
		if err != nil {
			gologger.Fatal().Msgf("Could not stream input: %s\n", err)
		}
	} else {
		r.prepareInput()

		// if resume is enabled inform the user
		if r.options.ShouldLoadResume() && r.options.resumeCfg.Index > 0 {
			gologger.Debug().Msgf("Resuming at position %d: %s\n", r.options.resumeCfg.Index, r.options.resumeCfg.ResumeFrom)
		}
	}

	// output routine
	var wgoutput sync.WaitGroup

	output := make(chan Result)
	nextStep := make(chan Result)

	wgoutput.Add(1)
	go func(output chan Result, nextSteps ...chan Result) {
		defer wgoutput.Done()

		defer func() {
			for _, nextStep := range nextSteps {
				close(nextStep)
			}
		}()

		var plainFile, jsonFile, csvFile, indexFile, indexScreenshotFile *os.File

		if r.options.Output != "" && r.options.OutputAll {
			plainFile = openOrCreateFile(r.options.Resume, r.options.Output)
			defer func() {
				_ = plainFile.Close()
			}()
			jsonFile = openOrCreateFile(r.options.Resume, r.options.Output+".json")
			defer func() {
				_ = jsonFile.Close()
			}()
			csvFile = openOrCreateFile(r.options.Resume, r.options.Output+".csv")
			defer func() {
				_ = csvFile.Close()
			}()
		}

		jsonOrCsv := (r.options.JSONOutput || r.options.CSVOutput)
		jsonAndCsv := (r.options.JSONOutput && r.options.CSVOutput)
		if r.options.Output != "" && plainFile == nil && !jsonOrCsv {
			plainFile = openOrCreateFile(r.options.Resume, r.options.Output)
			defer func() {
				_ = plainFile.Close()
			}()
		}

		if r.options.Output != "" && r.options.JSONOutput && jsonFile == nil {
			ext := ""
			if jsonAndCsv {
				ext = ".json"
			}
			jsonFile = openOrCreateFile(r.options.Resume, r.options.Output+ext)
			defer func() {
				_ = jsonFile.Close()
			}()
		}

		if r.options.Output != "" && r.options.CSVOutput && csvFile == nil {
			ext := ""
			if jsonAndCsv {
				ext = ".csv"
			}
			csvFile = openOrCreateFile(r.options.Resume, r.options.Output+ext)
			defer func() {
				_ = csvFile.Close()
			}()
		}

		if r.options.CSVOutput {
			outEncoding := strings.ToLower(r.options.CSVOutputEncoding)
			switch outEncoding {
			case "": // no encoding do nothing
			case "utf-8", "utf8":
				bomUtf8 := []byte{0xEF, 0xBB, 0xBF}
				_, err := csvFile.Write(bomUtf8)
				if err != nil {
					gologger.Fatal().Msgf("err on file write: %s\n", err)
				}
			default: // unknown encoding
				gologger.Fatal().Msgf("unknown csv output encoding: %s\n", r.options.CSVOutputEncoding)
			}
			headers := Result{}.CSVHeader()
			if !r.options.OutputAll && !jsonAndCsv {
				gologger.Silent().Msgf("%s\n", headers)
			}

			if csvFile != nil {
				//nolint:errcheck // this method needs a small refactor to reduce complexity
				csvFile.WriteString(headers + "\n")
			}
		}
		if r.options.StoreResponseDir != "" {
			var err error
			responseDirPath := filepath.Join(r.options.StoreResponseDir, "response")
			if err := os.MkdirAll(responseDirPath, 0755); err != nil {
				gologger.Fatal().Msgf("Could not create response directory '%s': %s\n", responseDirPath, err)
			}
			indexPath := filepath.Join(responseDirPath, "index.txt")
			// Append if resume is enabled or skip-dedupe is enabled (never truncate with -sd)
			if r.options.Resume || r.options.SkipDedupe {
				indexFile, err = os.OpenFile(indexPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			} else {
				indexFile, err = os.Create(indexPath)
			}
			if err != nil {
				gologger.Fatal().Msgf("Could not open/create index file '%s': %s\n", r.options.Output, err)
			}
			defer indexFile.Close() //nolint
		}

		if r.options.Screenshot {
			var err error
			indexScreenshotPath := filepath.Join(r.options.StoreResponseDir, "screenshot", "index_screenshot.txt")
			// Append if resume is enabled or skip-dedupe is enabled (never truncate with -sd)
			if r.options.Resume || r.options.SkipDedupe {
				indexScreenshotFile, err = os.OpenFile(indexScreenshotPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			} else {
				indexScreenshotFile, err = os.Create(indexScreenshotPath)
			}
			if err != nil {
				gologger.Fatal().Msgf("Could not open/create index screenshot file '%s': %s\n", r.options.Output, err)
			}
			defer indexScreenshotFile.Close() //nolint
		}

		for resp := range output {
			if r.options.SniName != "" {
				resp.SNI = r.options.SniName
			}

			if resp.Err != nil {
				// Change the error message if any port value passed explicitly
				if url, err := r.parseURL(resp.URL); err == nil && url.Port() != "" {
					resp.Err = errors.New(strings.ReplaceAll(resp.Err.Error(), "address", "port"))
				}
				gologger.Debug().Msgf("Failed '%s': %s\n", resp.URL, resp.Err)
			}
			if resp.str == "" {
				continue
			}

			// apply matchers and filters
			if r.options.OutputFilterCondition != "" || r.options.OutputMatchCondition != "" {
				if r.options.OutputMatchCondition != "" {
					matched := evalDslExpr(resp, r.options.OutputMatchCondition)
					if !matched {
						continue
					}
				}
				if r.options.OutputFilterCondition != "" {
					matched := evalDslExpr(resp, r.options.OutputFilterCondition)
					if matched {
						continue
					}
				}
			}

			if r.options.OutputFilterErrorPage && resp.KnowledgeBase["PageType"] == "error" {
				logFilteredErrorPage(r.options.OutputFilterErrorPagePath, resp.URL)
				continue
			}

			if r.options.FilterOutDuplicates && r.duplicate(&resp) {
				continue
			}

			if len(r.options.filterStatusCode) > 0 && sliceutil.Contains(r.options.filterStatusCode, resp.StatusCode) {
				continue
			}
			if len(r.options.filterContentLength) > 0 && sliceutil.Contains(r.options.filterContentLength, resp.ContentLength) {
				continue
			}
			if len(r.options.filterLinesCount) > 0 && sliceutil.Contains(r.options.filterLinesCount, resp.Lines) {
				continue
			}
			if len(r.options.filterWordsCount) > 0 && sliceutil.Contains(r.options.filterWordsCount, resp.Words) {
				continue
			}
			if r.options.filterRegexes != nil {
				shouldContinue := false
				for _, filterRegex := range r.options.filterRegexes {
					if filterRegex.MatchString(resp.Raw) {
						shouldContinue = true
						break
					}
				}
				if shouldContinue {
					continue
				}
			}
			if len(r.options.OutputFilterString) > 0 && stringsutil.ContainsAnyI(resp.Raw, r.options.OutputFilterString...) {
				continue
			}
			if len(r.options.OutputFilterFavicon) > 0 && stringsutil.ContainsAnyI(resp.FavIconMMH3, r.options.OutputFilterFavicon...) {
				continue
			}
			if len(r.options.matchStatusCode) > 0 && !sliceutil.Contains(r.options.matchStatusCode, resp.StatusCode) {
				continue
			}
			if len(r.options.matchContentLength) > 0 && !sliceutil.Contains(r.options.matchContentLength, resp.ContentLength) {
				continue
			}
			if r.options.matchRegexes != nil {
				shouldContinue := false
				for _, matchRegex := range r.options.matchRegexes {
					if !matchRegex.MatchString(resp.Raw) {
						shouldContinue = true
						break
					}
				}
				if shouldContinue {
					continue
				}
			}
			if len(r.options.OutputMatchString) > 0 && !stringsutil.ContainsAnyI(resp.Raw, r.options.OutputMatchString...) {
				continue
			}
			if len(r.options.OutputMatchFavicon) > 0 && !stringsutil.EqualFoldAny(resp.FavIconMMH3, r.options.OutputMatchFavicon...) {
				continue
			}
			if len(r.options.matchLinesCount) > 0 && !sliceutil.Contains(r.options.matchLinesCount, resp.Lines) {
				continue
			}
			if len(r.options.matchWordsCount) > 0 && !sliceutil.Contains(r.options.matchWordsCount, resp.Words) {
				continue
			}
			if len(r.options.OutputMatchCdn) > 0 && !stringsutil.EqualFoldAny(resp.CDNName, r.options.OutputMatchCdn...) {
				continue
			}
			if len(r.options.OutputFilterCdn) > 0 && stringsutil.EqualFoldAny(resp.CDNName, r.options.OutputFilterCdn...) {
				continue
			}

			if r.options.OutputMatchResponseTime != "" {
				filterOps := FilterOperator{flag: "-mrt, -match-response-time"}
				operator, value, err := filterOps.Parse(r.options.OutputMatchResponseTime)
				if err != nil {
					gologger.Fatal().Msg(err.Error())
				}
				respTimeTaken, _ := time.ParseDuration(resp.ResponseTime)
				switch operator {
				// take negation of >= and >
				case greaterThanEq, greaterThan:
					if respTimeTaken < value {
						continue
					}
				// take negation of <= and <
				case lessThanEq, lessThan:
					if respTimeTaken > value {
						continue
					}
				// take negation of =
				case equal:
					if respTimeTaken != value {
						continue
					}
				// take negation of !=
				case notEq:
					if respTimeTaken == value {
						continue
					}
				}
			}

			if r.options.OutputFilterResponseTime != "" {
				filterOps := FilterOperator{flag: "-frt, -filter-response-time"}
				operator, value, err := filterOps.Parse(r.options.OutputFilterResponseTime)
				if err != nil {
					gologger.Fatal().Msg(err.Error())
				}
				respTimeTaken, _ := time.ParseDuration(resp.ResponseTime)
				switch operator {
				case greaterThanEq:
					if respTimeTaken >= value {
						continue
					}
				case lessThanEq:
					if respTimeTaken <= value {
						continue
					}
				case equal:
					if respTimeTaken == value {
						continue
					}
				case lessThan:
					if respTimeTaken < value {
						continue
					}
				case greaterThan:
					if respTimeTaken > value {
						continue
					}
				case notEq:
					if respTimeTaken != value {
						continue
					}
				}
			}

			if !r.options.DisableStdout && (!jsonOrCsv || jsonAndCsv || r.options.OutputAll) {
				gologger.Silent().Msgf("%s\n", resp.str)
			}

			// store responses or chain in directory
			if resp.Err == nil {
				URL, _ := urlutil.Parse(resp.URL)
				domainResponseFile := fmt.Sprintf("%s.txt", resp.FileNameHash)
				screenshotResponseFile := fmt.Sprintf("%s.png", resp.FileNameHash)
				hostFilename := strings.ReplaceAll(URL.Host, ":", "_")
				domainResponseBaseDir := filepath.Join(r.options.StoreResponseDir, "response")
				domainScreenshotBaseDir := filepath.Join(r.options.StoreResponseDir, "screenshot")
				responseBaseDir := filepath.Join(domainResponseBaseDir, hostFilename)
				screenshotBaseDir := filepath.Join(domainScreenshotBaseDir, hostFilename)

				var responsePath, screenshotPath, screenshotPathRel string
				// store response
				if r.scanopts.StoreResponse || r.scanopts.StoreChain {
					if r.scanopts.OmitBody {
						resp.Raw = strings.ReplaceAll(resp.Raw, resp.ResponseBody, "")
					}

					responsePath = fileutilz.AbsPathOrDefault(filepath.Join(responseBaseDir, domainResponseFile))
					// URL.EscapedString returns that can be used as filename
					respRaw := resp.Raw
					reqRaw := resp.RequestRaw
					if len(respRaw) > r.scanopts.MaxResponseBodySizeToSave {
						respRaw = respRaw[:r.scanopts.MaxResponseBodySizeToSave]
					}
					data := reqRaw
					if r.options.StoreChain && resp.Response != nil && resp.Response.HasChain() {
						data = append(data, append([]byte("\n"), []byte(resp.Response.GetChain())...)...)
					}
					data = append(data, respRaw...)
					data = append(data, []byte("\n\n\n")...)
					data = append(data, []byte(resp.URL)...)
					_ = fileutil.CreateFolder(responseBaseDir)
					writeErr := os.WriteFile(responsePath, data, 0644)
					if writeErr != nil {
						gologger.Error().Msgf("Could not write response at path '%s', to disk: %s", responsePath, writeErr)
					}
					resp.StoredResponsePath = responsePath
				}

				if r.scanopts.Screenshot {
					screenshotPath = fileutilz.AbsPathOrDefault(filepath.Join(screenshotBaseDir, screenshotResponseFile))
					screenshotPathRel = filepath.Join(hostFilename, screenshotResponseFile)
					_ = fileutil.CreateFolder(screenshotBaseDir)
					err := os.WriteFile(screenshotPath, resp.ScreenshotBytes, 0644)
					if err != nil {
						gologger.Error().Msgf("Could not write screenshot at path '%s', to disk: %s", screenshotPath, err)
					}

					resp.ScreenshotPath = screenshotPath
					resp.ScreenshotPathRel = screenshotPathRel
					if r.scanopts.NoScreenshotBytes {
						resp.ScreenshotBytes = []byte{}
					}
				}

				if indexFile != nil {
					indexData := fmt.Sprintf("%s %s (%d %s)\n", resp.StoredResponsePath, resp.URL, resp.StatusCode, http.StatusText(resp.StatusCode))
					_, _ = indexFile.WriteString(indexData)
				}
				if indexScreenshotFile != nil && resp.ScreenshotPathRel != "" {
					indexData := fmt.Sprintf("%s %s (%d %s)\n", resp.ScreenshotPathRel, resp.URL, resp.StatusCode, http.StatusText(resp.StatusCode))
					_, _ = indexScreenshotFile.WriteString(indexData)
				}

				if r.scanopts.StoreVisionReconClusters {
					foundCluster := false
					pHash, _ := resp.KnowledgeBase["pHash"].(uint64)
					for i, cluster := range r.pHashClusters {
						distance, _ := goimagehash.NewImageHash(pHash, goimagehash.PHash).Distance(goimagehash.NewImageHash(cluster.BasePHash, goimagehash.PHash))
						if distance <= hammingDistanceThreshold {
							r.pHashClusters[i].Hashes = append(r.pHashClusters[i].Hashes, pHashUrl{PHash: pHash, Url: resp.URL})
							foundCluster = true
							break
						}
					}

					if !foundCluster {
						newCluster := pHashCluster{
							BasePHash: pHash,
							Hashes:    []pHashUrl{{PHash: pHash, Url: resp.URL}},
						}
						r.pHashClusters = append(r.pHashClusters, newCluster)
					}
				}
			}

			//nolint:errcheck // this method needs a small refactor to reduce complexity
			if plainFile != nil {
				plainFile.WriteString(handleStripAnsiCharacters(resp.str, r.options.NoColor) + "\n")
			}

			if len(r.options.ExcludeOutputFields) > 0 {
				if filteredData, err := structs.FilterStruct(resp, nil, r.options.ExcludeOutputFields); err == nil {
					resp = filteredData
				}
			}

			// call the callback function if any
			// be careful and check for result.Err
			if r.options.OnResult != nil {
				r.options.OnResult(resp)
			}

			if r.options.JSONOutput {
				row := resp.JSON(&r.scanopts)

				if !r.options.OutputAll && !jsonAndCsv {
					gologger.Silent().Msgf("%s\n", row)
				}

				//nolint:errcheck // this method needs a small refactor to reduce complexity
				if jsonFile != nil {
					jsonFile.WriteString(row + "\n")
				}
			}

			if r.options.CSVOutput {
				row := resp.CSVRow(&r.scanopts)

				if !r.options.OutputAll && !jsonAndCsv {
					gologger.Silent().Msgf("%s\n", row)
				}

				//nolint:errcheck // this method needs a small refactor to reduce complexity
				if csvFile != nil {
					csvFile.WriteString(row + "\n")
				}
			}

			for _, nextStep := range nextSteps {
				nextStep <- resp
			}
		}
	}(output, nextStep)

	// HTML Summary
	// - needs output of previous routine
	// - separate goroutine due to incapability of go templates to render from file
	wgoutput.Add(1)
	go func(output chan Result) {
		defer wgoutput.Done()

		if r.options.Screenshot {
			screenshotHtmlPath := filepath.Join(r.options.StoreResponseDir, "screenshot", "screenshot.html")
			screenshotHtml, err := os.Create(screenshotHtmlPath)
			if err != nil {
				gologger.Warning().Msgf("Could not create HTML file %s\n", err)
			}
			defer func() {
				_ = screenshotHtml.Close()
			}()

			templateMap := template.FuncMap{
				"safeURL": func(u string) template.URL {
					if osutil.IsWindows() {
						u = filepath.ToSlash(u)
					}
					return template.URL(u)
				},
			}
			tmpl, err := template.
				New("screenshotTemplate").
				Funcs(templateMap).
				Parse(static.HtmlTemplate)
			if err != nil {
				gologger.Warning().Msgf("Could not create HTML template: %v\n", err)
			}

			if err = tmpl.Execute(screenshotHtml, struct {
				Options Options
				Output  chan Result
			}{
				Options: *r.options,
				Output:  output,
			}); err != nil {
				gologger.Warning().Msgf("Could not execute HTML template: %v\n", err)
			}
		}

		// fallthrough if anything is left in the buffer unblocks if screenshot is false
		for range output {
		}
	}(nextStep)

	wg, _ := syncutil.New(syncutil.WithSize(r.options.Threads))

	processItem := func(k string) error {
		if r.options.resumeCfg != nil {
			r.options.resumeCfg.current = k
			r.options.resumeCfg.currentIndex++
			if r.options.resumeCfg.currentIndex <= r.options.resumeCfg.Index {
				return nil
			}
		}

		protocol := r.options.protocol
		// attempt to parse url as is
		if u, err := r.parseURL(k); err == nil {
			if r.options.NoFallbackScheme && u.Scheme == httpx.HTTP || u.Scheme == httpx.HTTPS {
				protocol = u.Scheme
			}
		}

		runProcess := func(times int) {
			for i := 0; i < times; i++ {
				if len(r.options.requestURIs) > 0 {
					for _, p := range r.options.requestURIs {
						scanopts := r.scanopts.Clone()
						scanopts.RequestURI = p
						r.process(k, wg, r.hp, protocol, scanopts, output)
					}
				} else {
					r.process(k, wg, r.hp, protocol, &r.scanopts, output)
				}
			}
		}

		if r.options.Stream {
			runProcess(1)
		} else if v, ok := r.hm.Get(k); ok {
			cnt, err := strconv.Atoi(string(v))
			if err != nil || cnt <= 0 {
				cnt = 1
			}
			runProcess(cnt)
		}

		return nil
	}

	if r.options.Stream {
		for item := range streamChan {
			_ = processItem(item)
		}
	} else {
		r.hm.Scan(func(k, _ []byte) error {
			return processItem(string(k))
		})
	}

	wg.Wait()

	close(output)

	wgoutput.Wait()

	if r.scanopts.StoreVisionReconClusters {
		visionReconClusters := filepath.Join(r.options.StoreResponseDir, "vision_recon_clusters.json")
		clusterReportJSON, err := json.Marshal(r.pHashClusters)
		if err != nil {
			gologger.Fatal().Msgf("Failed to marshal report to JSON: %v", err)
		}
		file, err := os.Create(visionReconClusters)
		if err != nil {
			gologger.Fatal().Msgf("Failed to create JSON file: %v", err)
		}
		defer func() {
			_ = file.Close()
		}()

		_, err = file.Write(clusterReportJSON)
		if err != nil {
			gologger.Fatal().Msgf("Failed to write to JSON file: %v", err)
		}
	}
}

func handleStripAnsiCharacters(data string, skip bool) string {
	if skip {
		return data
	}
	return stripANSI(data)
}

func logFilteredErrorPage(fileName, url string) {
	dir := filepath.Dir(fileName)
	if !fileutil.FolderExists(dir) {
		err := fileutil.CreateFolder(dir)
		if err != nil {
			gologger.Fatal().Msgf("Could not create directory '%s': %s\n", dir, err)
			return
		}
	}

	file, err := fileutil.OpenOrCreateFile(fileName)
	if err != nil {
		gologger.Fatal().Msgf("Could not open/create output file '%s': %s\n", fileName, err)
		return
	}
	defer func() {
		_ = file.Close()
	}()

	info := map[string]interface{}{
		"url":           url,
		"time_filtered": time.Now(),
	}

	data, err := json.Marshal(info)
	if err != nil {
		fmt.Println("Failed to marshal JSON:", err)
		return
	}

	if _, err := file.Write(data); err != nil {
		gologger.Fatal().Msgf("Failed to write to '%s': %s\n", fileName, err)
		return
	}

	if _, err := file.WriteString("\n"); err != nil {
		gologger.Fatal().Msgf("Failed to write newline to '%s': %s\n", fileName, err)
		return
	}
}

func openOrCreateFile(resume bool, filename string) *os.File {
	var err error
	var f *os.File
	if resume {
		f, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	} else {
		f, err = os.Create(filename)
	}
	if err != nil {
		gologger.Fatal().Msgf("Could not open/create output file '%s': %s\n", filename, err)
	}
	return f
}

func (r *Runner) GetScanOpts() ScanOptions {
	return r.scanopts
}

func (r *Runner) Process(t string, wg *syncutil.AdaptiveWaitGroup, protocol string, scanopts *ScanOptions, output chan Result) {
	r.process(t, wg, r.hp, protocol, scanopts, output)
}

func (r *Runner) process(t string, wg *syncutil.AdaptiveWaitGroup, hp *httpx.HTTPX, protocol string, scanopts *ScanOptions, output chan Result) {
	// attempts to set the workpool size to the number of threads
	if r.options.Threads > 0 && wg.Size != r.options.Threads {
		if err := wg.Resize(context.Background(), r.options.Threads); err != nil {
			gologger.Error().Msgf("Could not resize workpool: %s\n", err)
		}
	}

	protocols := []string{protocol}
	if scanopts.NoFallback || protocol == httpx.HTTPandHTTPS {
		protocols = []string{httpx.HTTPS, httpx.HTTP}
	}

	for target := range r.targets(hp, t) {
		// if no custom ports specified then test the default ones
		if len(customport.Ports) == 0 {
			for _, method := range scanopts.Methods {
				for _, prot := range protocols {
					// sleep for delay time
					time.Sleep(r.options.Delay)
					wg.Add()
					go func(target httpx.Target, method, protocol string) {
						defer wg.Done()
						result := r.analyze(hp, protocol, target, method, t, scanopts)
						output <- result
						if scanopts.TLSProbe && result.TLSData != nil {
							for _, tt := range result.TLSData.SubjectAN {
								if !r.testAndSet(tt) {
									continue
								}
								r.process(tt, wg, hp, protocol, scanopts, output)
							}
							if r.testAndSet(result.TLSData.SubjectCN) {
								r.process(result.TLSData.SubjectCN, wg, hp, protocol, scanopts, output)
							}
						}
						if scanopts.CSPProbe && result.CSPData != nil {
							scanopts.CSPProbe = false
							domains := result.CSPData.Domains
							domains = append(domains, result.CSPData.Fqdns...)
							for _, tt := range domains {
								if !r.testAndSet(tt) {
									continue
								}
								r.process(tt, wg, hp, protocol, scanopts, output)
							}
						}
					}(target, method, prot)
				}
			}
		}

		for port, wantedProtocolForPort := range customport.Ports {
			// NoFallbackScheme overrides custom ports scheme
			// Example: httpx -u https://www.example.com -ports http:8080,https:443 --no-fallback-scheme
			// In this case, the requests will be created with the target scheme (ignoring the custom ports scheme)
			// Examples: https://www.example.com:8080 and https://www.example.com:443
			if scanopts.NoFallbackScheme {
				wantedProtocolForPort = protocol
			}
			wantedProtocols := []string{wantedProtocolForPort}
			if wantedProtocolForPort == httpx.HTTPandHTTPS {
				wantedProtocols = []string{httpx.HTTPS, httpx.HTTP}
			}
			for _, wantedProtocol := range wantedProtocols {
				for _, method := range scanopts.Methods {
					// sleep for delay time
					time.Sleep(r.options.Delay)
					wg.Add()
					go func(port int, target httpx.Target, method, protocol string) {
						defer wg.Done()
						if urlx, err := r.parseURL(target.Host); err != nil {
							gologger.Warning().Msgf("failed to update port of %v got %v", target.Host, err)
						} else {
							urlx.UpdatePort(fmt.Sprint(port))
							target.Host = urlx.String()
						}
						result := r.analyze(hp, protocol, target, method, t, scanopts)
						output <- result
						if scanopts.TLSProbe && result.TLSData != nil {
							for _, tt := range result.TLSData.SubjectAN {
								if !r.testAndSet(tt) {
									continue
								}
								r.process(tt, wg, hp, protocol, scanopts, output)
							}
							if r.testAndSet(result.TLSData.SubjectCN) {
								r.process(result.TLSData.SubjectCN, wg, hp, protocol, scanopts, output)
							}
						}
					}(port, target, method, wantedProtocol)
				}
			}
		}
		if r.options.ShowStatistics {
			r.stats.IncrementCounter("hosts", 1)
		}
	}
}

// returns all the targets within a cidr range or the single target
func (r *Runner) targets(hp *httpx.HTTPX, target string) chan httpx.Target {
	results := make(chan httpx.Target)
	go func() {
		defer close(results)

		target = strings.TrimSpace(target)

		switch {
		case stringsutil.HasPrefixAny(target, "*", "."):
			// A valid target does not contain:
			// trim * and/or . (prefix) from the target to return the domain instead of wildcard
			target = stringsutil.TrimPrefixAny(target, "*", ".")
			if !r.testAndSet(target) {
				return
			}
			results <- httpx.Target{Host: target}
		case asn.IsASN(target):
			cidrIps, err := asn.GetIPAddressesAsStream(target)
			if err != nil {
				gologger.Warning().Msgf("Could not get ASN targets for '%s': %s\n", target, err)
				return
			}
			for ip := range cidrIps {
				results <- httpx.Target{Host: ip}
			}
		case iputil.IsCIDR(target):
			cidrIps, err := mapcidr.IPAddressesAsStream(target)
			if err != nil {
				return
			}
			for ip := range cidrIps {
				results <- httpx.Target{Host: ip}
			}
		case r.options.ProbeAllIPS:
			URL, err := r.parseURL(target)
			if err != nil {
				results <- httpx.Target{Host: target}
				return
			}
			ips, _, _, err := getDNSData(hp, URL.Hostname())
			if err != nil || len(ips) == 0 {
				results <- httpx.Target{Host: target}
				return
			}
			for _, ip := range ips {
				results <- httpx.Target{Host: target, CustomIP: ip}
			}
		case !stringsutil.HasPrefixAny(target, "http://", "https://") && stringsutil.ContainsAny(target, ","):
			idxComma := strings.Index(target, ",")
			results <- httpx.Target{Host: target[idxComma+1:], CustomHost: target[:idxComma]}
		default:
			results <- httpx.Target{Host: target}
		}
	}()
	return results
}

func (r *Runner) analyze(hp *httpx.HTTPX, protocol string, target httpx.Target, method, origInput string, scanopts *ScanOptions) Result {
	origProtocol := protocol
	if protocol == httpx.HTTPorHTTPS || protocol == httpx.HTTPandHTTPS {
		protocol = determineMostLikelySchemeOrder(target.Host)
	}
	retried := false
retry:
	if scanopts.VHostInput && target.CustomHost == "" {
		return Result{Input: origInput}
	}
	URL, err := r.parseURL(target.Host)
	if err != nil {
		return Result{URL: target.Host, Input: origInput, Err: err}
	}

	// check if we have to skip the host:port as a result of a previous failure
	hostPort := net.JoinHostPort(URL.Host, URL.Port())
	if r.options.HostMaxErrors >= 0 && r.HostErrorsCache.Has(hostPort) {
		numberOfErrors, err := r.HostErrorsCache.GetIFPresent(hostPort)
		if err == nil && numberOfErrors >= r.options.HostMaxErrors {
			return Result{URL: target.Host, Err: errors.New("skipping as previously unresponsive")}
		}
	}

	// check if the combination host:port should be skipped if belonging to a cdn
	skip, reason := r.skip(URL, target, origInput)
	if skip {
		return reason
	}

	URL.Scheme = protocol

	if !strings.Contains(target.Host, URL.Port()) {
		URL.TrimPort()
	}

	var reqURI string
	// retry with unsafe
	if err := URL.MergePath(scanopts.RequestURI, scanopts.Unsafe); err != nil {
		gologger.Debug().Msgf("failed to merge paths of url %v and %v", URL.String(), scanopts.RequestURI)
	}
	var (
		req *retryablehttp.Request
		ctx context.Context
	)
	if target.CustomIP != "" {
		var requestIP string
		if iputil.IsIPv6(target.CustomIP) {
			requestIP = fmt.Sprintf("[%s]", target.CustomIP)
		} else {
			requestIP = target.CustomIP
		}
		ctx = context.WithValue(context.Background(), fastdialer.IP, requestIP)
	} else {
		ctx = context.Background()
	}
	req, err = hp.NewRequestWithContext(ctx, method, URL.String())
	if err != nil {
		return Result{URL: URL.String(), Input: origInput, Err: err}
	}

	if target.CustomHost != "" {
		req.Host = target.CustomHost
	}

	if !scanopts.LeaveDefaultPorts {
		switch {
		case protocol == httpx.HTTP && strings.HasSuffix(req.Host, ":80"):
			req.Host = strings.TrimSuffix(req.Host, ":80")
		case protocol == httpx.HTTPS && strings.HasSuffix(req.Host, ":443"):
			req.Host = strings.TrimSuffix(req.Host, ":443")
		}
	}

	hp.SetCustomHeaders(req, hp.CustomHeaders)

	// Apply auth strategies if auth provider is configured
	if r.authProvider != nil {
		if strategies := r.authProvider.LookupURLX(URL); len(strategies) > 0 {
			for _, strategy := range strategies {
				strategy.ApplyOnRR(req)
			}
		}
	}

	// We set content-length even if zero to allow net/http to follow 307/308 redirects (it fails on unknown size)
	if scanopts.RequestBody != "" {
		req.ContentLength = int64(len(scanopts.RequestBody))
		req.Body = io.NopCloser(strings.NewReader(scanopts.RequestBody))
	} else {
		req.ContentLength = 0
		req.Body = nil
	}

	r.ratelimiter.Take()

	// with rawhttp we should say to the server to close the connection, otherwise it will remain open
	if scanopts.Unsafe {
		req.Header.Add("Connection", "close")
	}
	resp, err := hp.Do(req, httpx.UnsafeOptions{URIPath: reqURI})
	if r.options.ShowStatistics {
		r.stats.IncrementCounter("requests", 1)
	}
	var requestDump []byte
	if scanopts.Unsafe {
		var errDump error
		requestDump, errDump = rawhttp.DumpRequestRaw(req.Method, req.String(), reqURI, req.Header, req.Body, rawhttp.DefaultOptions)
		if errDump != nil {
			return Result{URL: URL.String(), Input: origInput, Err: errDump}
		}
	} else {
		// Create a copy on the fly of the request body
		if scanopts.RequestBody != "" {
			req.ContentLength = int64(len(scanopts.RequestBody))
			req.Body = io.NopCloser(strings.NewReader(scanopts.RequestBody))
		}
		var errDump error
		requestDump, errDump = httputil.DumpRequestOut(req.Request, true)
		if errDump != nil {
			return Result{URL: URL.String(), Input: origInput, Err: errDump}
		}
		// The original req.Body gets modified indirectly by httputil.DumpRequestOut so we set it again to nil if it was empty
		// Otherwise redirects like 307/308 would fail (as they require the body to be sent along)
		if len(scanopts.RequestBody) == 0 {
			req.ContentLength = 0
			req.Body = nil
		}
	}
	// fix the final output url
	fullURL := req.String()
	if parsedURL, errParse := r.parseURL(fullURL); errParse != nil {
		return Result{URL: URL.String(), Input: origInput, Err: errParse}
	} else {
		if r.options.Unsafe {
			parsedURL.Path = reqURI
			// if the full url doesn't end with the custom path we pick the original input value
		} else if !stringsutil.HasSuffixAny(fullURL, scanopts.RequestURI) {
			parsedURL.Path = scanopts.RequestURI
		}
		fullURL = parsedURL.String()
	}

	if r.options.Debug || r.options.DebugRequests {
		gologger.Info().Msgf("Dumped HTTP request for %s\n\n", fullURL)
		gologger.Print().Msgf("%s", string(requestDump))
	}
	if (r.options.Debug || r.options.DebugResponse) && resp != nil {
		gologger.Info().Msgf("Dumped HTTP response for %s\n\n", fullURL)
		gologger.Print().Msgf("%s", string(resp.Raw))
	}

	builder := &strings.Builder{}
	if scanopts.LeaveDefaultPorts {
		builder.WriteString(stringz.AddURLDefaultPort(fullURL))
	} else {
		builder.WriteString(stringz.RemoveURLDefaultPort(fullURL))
	}

	if r.options.Probe {
		builder.WriteString(" [")

		outputStatus := "SUCCESS"
		if err != nil {
			outputStatus = "FAILED"
		}

		if !scanopts.OutputWithNoColor && err != nil {
			builder.WriteString(aurora.Red(outputStatus).String())
		} else if !scanopts.OutputWithNoColor && err == nil {
			builder.WriteString(aurora.Green(outputStatus).String())
		} else {
			builder.WriteString(outputStatus)
		}

		builder.WriteRune(']')
	}
	if err != nil {
		errString := ""
		errString = err.Error()
		splitErr := strings.Split(errString, ":")
		errString = strings.TrimSpace(splitErr[len(splitErr)-1])

		if !retried && origProtocol == httpx.HTTPorHTTPS {
			// switch protocol and adjust port accordingly
			if protocol == httpx.HTTPS {
				protocol = httpx.HTTP
				// if port is 443 (default HTTPS), switch to 80 (default HTTP)
				if URL.Port() == "443" {
					URL.UpdatePort("80")
					target.Host = net.JoinHostPort(URL.Hostname(), "80")
				}
			} else {
				protocol = httpx.HTTPS
				// if port is 80 (default HTTP), switch to 443 (default HTTPS)
				if URL.Port() == "80" {
					URL.UpdatePort("443")
					target.Host = net.JoinHostPort(URL.Hostname(), "443")
				}
			}
			retried = true
			goto retry
		}

		// mark the host:port as failed to avoid further checks
		if r.options.HostMaxErrors >= 0 {
			errorCount, err := r.HostErrorsCache.GetIFPresent(hostPort)
			if err != nil || errorCount == 0 {
				_ = r.HostErrorsCache.Set(hostPort, 1)
			} else if errorCount > 0 {
				_ = r.HostErrorsCache.Set(hostPort, errorCount+1)
			}
		}

		if r.options.Probe {
			return Result{URL: URL.String(), Input: origInput, Timestamp: time.Now(), Err: err, Failed: err != nil, Error: errString, str: builder.String()}
		} else {
			return Result{URL: URL.String(), Input: origInput, Timestamp: time.Now(), Err: err}
		}
	}

	if scanopts.OutputStatusCode {
		builder.WriteString(" [")
		setColor := func(statusCode int) {
			if !scanopts.OutputWithNoColor {
				// Color the status code based on its value
				switch {
				case statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices:
					builder.WriteString(aurora.Green(strconv.Itoa(statusCode)).String())
				case statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest:
					builder.WriteString(aurora.Yellow(strconv.Itoa(statusCode)).String())
				case statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError:
					builder.WriteString(aurora.Red(strconv.Itoa(statusCode)).String())
				case resp.StatusCode > http.StatusInternalServerError:
					builder.WriteString(aurora.Bold(aurora.Yellow(strconv.Itoa(statusCode))).String())
				}
			} else {
				builder.WriteString(strconv.Itoa(statusCode))
			}
		}
		for i, chainItem := range resp.Chain {
			setColor(chainItem.StatusCode)
			if i != len(resp.Chain)-1 {
				builder.WriteRune(',')
			}
		}
		if r.options.Unsafe {
			setColor(resp.StatusCode)
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputLocation {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(resp.GetHeaderPart("Location", ";")).String())
		} else {
			builder.WriteString(resp.GetHeaderPart("Location", ";"))
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputMethod {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(method).String())
		} else {
			builder.WriteString(method)
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputContentLength {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(strconv.Itoa(resp.ContentLength)).String())
		} else {
			builder.WriteString(strconv.Itoa(resp.ContentLength))
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputContentType {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(resp.GetHeaderPart("Content-Type", ";")).String())
		} else {
			builder.WriteString(resp.GetHeaderPart("Content-Type", ";"))
		}
		builder.WriteRune(']')
	}

	var title string
	if httpx.CanHaveTitleTag(resp.GetHeaderPart("Content-Type", ";")) {
		title = httpx.ExtractTitle(resp)
	}

	if scanopts.OutputTitle && title != "" {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Cyan(title).String())
		} else {
			builder.WriteString(title)
		}
		builder.WriteRune(']')
	}

	var bodyPreview string
	if r.options.ResponseBodyPreviewSize > 0 && resp != nil {
		bodyPreview = string(resp.Data)
		if stringsutil.EqualFoldAny(r.options.StripFilter, "html", "xml") {
			bodyPreview = r.hp.Sanitize(bodyPreview, true, true)
		} else {
			bodyPreview = strings.ReplaceAll(bodyPreview, "\n", "\\n")
			bodyPreview = httputilz.NormalizeSpaces(bodyPreview)
		}
		if len(bodyPreview) > r.options.ResponseBodyPreviewSize {
			bodyPreview = bodyPreview[:r.options.ResponseBodyPreviewSize]
		}
		bodyPreview = strings.TrimSpace(bodyPreview)
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Blue(bodyPreview).String())
		} else {
			builder.WriteString(bodyPreview)
		}
		builder.WriteRune(']')
	}

	serverHeader := resp.GetHeader("Server")
	if scanopts.OutputServerHeader {
		_, _ = fmt.Fprintf(builder, " [%s]", serverHeader)
	}

	var (
		serverResponseRaw  string
		request            string
		rawResponseHeaders string
		responseHeaders    map[string]interface{}
		linkRequest        []NetworkRequest
	)

	if scanopts.ResponseHeadersInStdout {
		responseHeaders = normalizeHeaders(resp.Headers)
	}

	respData := string(resp.Data)
	if r.options.NoDecode {
		respData = string(resp.RawData)
	}

	if scanopts.ResponseInStdout || r.options.OutputMatchCondition != "" || r.options.OutputFilterCondition != "" {
		serverResponseRaw = string(respData)
		request = string(requestDump)
		responseHeaders = normalizeHeaders(resp.Headers)
		rawResponseHeaders = resp.RawHeaders
	} else if scanopts.Base64ResponseInStdout {
		serverResponseRaw = stringz.Base64([]byte(respData))
		request = stringz.Base64(requestDump)
		responseHeaders = normalizeHeaders(resp.Headers)
		rawResponseHeaders = stringz.Base64([]byte(resp.RawHeaders))
	}

	// check for virtual host
	isvhost := false
	if scanopts.VHost {
		r.ratelimiter.Take()
		isvhost, _ = hp.IsVirtualHost(req, httpx.UnsafeOptions{})
		if isvhost {
			builder.WriteString(" [vhost]")
		}
	}

	// web socket
	isWebSocket := isWebSocket(resp)
	if scanopts.OutputWebSocket && isWebSocket {
		builder.WriteString(" [websocket]")
	}

	pipeline := false
	if scanopts.Pipeline {
		port, _ := strconv.Atoi(URL.Port())
		r.ratelimiter.Take()
		pipeline = hp.SupportPipeline(protocol, method, URL.Host, port)
		if pipeline {
			builder.WriteString(" [pipeline]")
		}
		if r.options.ShowStatistics {
			r.stats.IncrementCounter("requests", 1)
		}
	}

	var http2 bool
	// if requested probes for http2
	if scanopts.HTTP2Probe {
		r.ratelimiter.Take()
		http2 = hp.SupportHTTP2(protocol, method, URL.String())
		if http2 {
			builder.WriteString(" [http2]")
		}
		if r.options.ShowStatistics {
			r.stats.IncrementCounter("requests", 1)
		}
	}

	var ip string
	if target.CustomIP != "" {
		ip = target.CustomIP
	} else {
		if onlyHost, _, err := net.SplitHostPort(URL.Host); err == nil && iputil.IsIP(onlyHost) {
			ip = onlyHost
		} else {
			// hp.Dialer.GetDialedIP would return only the last dialed one
			ip = hp.Dialer.GetDialedIP(URL.Host)
			if ip == "" {
				ip = hp.Dialer.GetDialedIP(onlyHost)
			}
		}
	}

	var asnResponse *AsnResponse
	if r.options.Asn {
		results, _ := asnmap.DefaultClient.GetData(ip)
		if len(results) > 0 {
			var cidrs []string
			ipnets, _ := asnmap.GetCIDR(results)
			for _, ipnet := range ipnets {
				cidrs = append(cidrs, ipnet.String())
			}
			asnResponse = &AsnResponse{
				AsNumber:  fmt.Sprintf("AS%v", results[0].ASN),
				AsName:    results[0].Org,
				AsCountry: results[0].Country,
				AsRange:   cidrs,
			}
			builder.WriteString(" [")
			if !scanopts.OutputWithNoColor {
				builder.WriteString(aurora.Magenta(asnResponse.String()).String())
			} else {
				builder.WriteString(asnResponse.String())
			}
			builder.WriteRune(']')
		}
	}

	if scanopts.OutputIP || scanopts.ProbeAllIPS {
		_, _ = fmt.Fprintf(builder, " [%s]", ip)
	}

	var onlyHost string
	onlyHost, _, err = net.SplitHostPort(URL.Host)
	if err != nil {
		onlyHost = URL.Host
	}
	allIps, cnames, resolvers, err := getDNSData(hp, onlyHost)
	if err != nil {
		allIps = append(allIps, ip)
	}

	var ips4, ips6 []string
	for _, ip := range allIps {
		switch {
		case iputil.IsIPv4(ip):
			ips4 = append(ips4, ip)
		case iputil.IsIPv6(ip):
			ips6 = append(ips6, ip)
		}
	}

	if scanopts.OutputCName && len(cnames) > 0 {
		// Print only the first CNAME (full list in json)
		_, _ = fmt.Fprintf(builder, " [%s]", cnames[0])
	}

	isCDN, cdnName, cdnType, err := hp.CdnCheck(ip)
	if scanopts.OutputCDN == "true" && isCDN && err == nil {
		_, _ = fmt.Fprintf(builder, " [%s]", cdnName)
	}

	if scanopts.OutputResponseTime {
		_, _ = fmt.Fprintf(builder, " [%s]", resp.Duration)
	}

	technologyDetails := make(map[string]wappalyzer.AppInfo)
	var technologies []string
	if scanopts.TechDetect {
		matches := r.wappalyzer.FingerprintWithInfo(resp.Headers, resp.Data)
		for match, data := range matches {
			technologies = append(technologies, match)
			technologyDetails[match] = data
		}
	}

	var extractRegex []string
	// extract regex
	var extractResult = map[string][]string{}
	if scanopts.extractRegexps != nil {
		for regex, compiledRegex := range scanopts.extractRegexps {
			matches := compiledRegex.FindAllString(string(resp.Raw), -1)
			if len(matches) > 0 {
				matches = sliceutil.Dedupe(matches)
				builder.WriteString(" [" + strings.Join(matches, ",") + "]")
				extractResult[regex] = matches
			}
		}
	}

	var finalURL string
	if resp.HasChain() {
		// Populate finalURL with the last URL in the chain, but just print it out in CLI mode if OutputLocation is set.
		// This way, we can still use the finalURL in JSON output.
		finalURL = resp.GetChainLastURL()
		if scanopts.OutputLocation {
			builder.WriteString(" [")
			if !scanopts.OutputWithNoColor {
				builder.WriteString(aurora.Magenta(finalURL).String())
			} else {
				builder.WriteString(finalURL)
			}
			builder.WriteRune(']')
		}
	}

	var faviconMMH3, faviconMD5, faviconPath, faviconURL string
	var faviconData []byte
	if scanopts.Favicon {
		var err error
		faviconMMH3, faviconMD5, faviconPath, faviconData, faviconURL, err = r.HandleFaviconHash(hp, req, resp.Data, finalURL, true)
		if err == nil {
			builder.WriteString(" [")
			if !scanopts.OutputWithNoColor {
				builder.WriteString(aurora.Magenta(faviconMMH3).String())
			} else {
				builder.WriteString(faviconMMH3)
			}
			builder.WriteRune(']')
		} else {
			gologger.Warning().Msgf("could not calculate favicon hash for path %v : %s", faviconPath, err)
		}
	}

	hashesMap := make(map[string]interface{})
	if scanopts.Hashes != "" {
		hs := strings.Split(scanopts.Hashes, ",")
		outputHashes := !(r.options.JSONOutput || r.options.OutputAll) //nolint
		if outputHashes {
			builder.WriteString(" [")
		}
		for index, hashType := range hs {
			var (
				hashHeader, hashBody string
			)
			hashType = strings.ToLower(hashType)
			switch hashType {
			case "md5":
				hashBody = hashes.Md5(resp.Data)
				hashHeader = hashes.Md5([]byte(resp.RawHeaders))
			case "mmh3":
				hashBody = hashes.Mmh3(resp.Data)
				hashHeader = hashes.Mmh3([]byte(resp.RawHeaders))
			case "sha1":
				hashBody = hashes.Sha1(resp.Data)
				hashHeader = hashes.Sha1([]byte(resp.RawHeaders))
			case "sha256":
				hashBody = hashes.Sha256(resp.Data)
				hashHeader = hashes.Sha256([]byte(resp.RawHeaders))
			case "sha512":
				hashBody = hashes.Sha512(resp.Data)
				hashHeader = hashes.Sha512([]byte(resp.RawHeaders))
			case "simhash":
				hashBody = hashes.Simhash(resp.Data)
				hashHeader = hashes.Simhash([]byte(resp.RawHeaders))
			}
			if hashBody != "" {
				hashesMap[fmt.Sprintf("body_%s", hashType)] = hashBody
				hashesMap[fmt.Sprintf("header_%s", hashType)] = hashHeader
				if outputHashes {
					if !scanopts.OutputWithNoColor {
						builder.WriteString(aurora.Magenta(hashBody).String())
					} else {
						builder.WriteString(hashBody)
					}
					if index != len(hs)-1 {
						builder.WriteString(",")
					}
				}
			}
		}
		if outputHashes {
			builder.WriteRune(']')
		}
	}
	if scanopts.OutputLinesCount {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(resp.Lines).String())
		} else {
			_, _ = fmt.Fprintf(builder, "%d", resp.Lines)
		}
		builder.WriteRune(']')
	}
	jarmhash := ""
	if r.options.Jarm {
		jarmhash = jarm.Jarm(r.hp.Dialer, fullURL, r.options.Timeout)
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(jarmhash).String())
		} else {
			_, _ = fmt.Fprintf(builder, "%s", jarmhash)
		}
		builder.WriteRune(']')
	}
	if scanopts.OutputWordsCount {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(resp.Words).String())
		} else {
			_, _ = fmt.Fprintf(builder, "%d", resp.Words)
		}
		builder.WriteRune(']')
	}

	// store responses or chain in directory
	domainFile := method + ":" + URL.EscapedString()
	hash := hashes.Sha1([]byte(domainFile))
	domainResponseFile := fmt.Sprintf("%s.txt", hash)
	hostFilename := strings.ReplaceAll(URL.Host, ":", "_")

	domainResponseBaseDir := filepath.Join(scanopts.StoreResponseDirectory, "response")
	responseBaseDir := filepath.Join(domainResponseBaseDir, hostFilename)

	var responsePath, fileNameHash string
	// store response
	if scanopts.StoreResponse || scanopts.StoreChain {
		if r.options.OmitBody {
			resp.Raw = strings.ReplaceAll(resp.Raw, string(resp.Data), "")
		}
		responsePath = fileutilz.AbsPathOrDefault(filepath.Join(responseBaseDir, domainResponseFile))
		// URL.EscapedString returns that can be used as filename
		respRaw := resp.Raw
		reqRaw := requestDump
		if len(respRaw) > scanopts.MaxResponseBodySizeToSave {
			respRaw = respRaw[:scanopts.MaxResponseBodySizeToSave]
		}
		data := reqRaw
		if scanopts.StoreChain && resp.HasChain() {
			data = append(data, append([]byte("\n"), []byte(resp.GetChain())...)...)
		}
		data = append(data, respRaw...)
		data = append(data, []byte("\n\n\n")...)
		data = append(data, []byte(fullURL)...)
		_ = fileutil.CreateFolder(responseBaseDir)

		basePath := strings.TrimSuffix(responsePath, ".txt")
		var idx int
		for idx = 0; ; idx++ {
			targetPath := responsePath
			if idx > 0 {
				targetPath = fmt.Sprintf("%s_%d.txt", basePath, idx)
			}
			f, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err == nil {
				_, writeErr := f.Write(data)
				_ = f.Close()
				if writeErr != nil {
					gologger.Error().Msgf("Could not write to '%s': %s", targetPath, writeErr)
				}
				break
			}
			if !os.IsExist(err) {
				gologger.Error().Msgf("Failed to create file '%s': %s", targetPath, err)
				break
			}
		}

		if idx == 0 {
			fileNameHash = hash
		} else {
			fileNameHash = fmt.Sprintf("%s_%d", hash, idx)
		}
	}

	parsed, err := r.parseURL(fullURL)
	if err != nil {
		return Result{URL: fullURL, Input: origInput, Err: errors.Wrap(err, "could not parse url")}
	}

	finalPort := parsed.Port()
	if finalPort == "" {
		if parsed.Scheme == "http" {
			finalPort = "80"
		} else {
			finalPort = "443"
		}
	}
	finalPath := parsed.RequestURI()
	if finalPath == "" {
		finalPath = "/"
	}
	var chainStatusCodes []int
	if resp.HasChain() {
		chainStatusCodes = append(chainStatusCodes, resp.GetChainStatusCodes()...)
	}
	var chainItems []httpx.ChainItem
	if scanopts.ChainInStdout && resp.HasChain() {
		chainItems = append(chainItems, resp.GetChainAsSlice()...)
	}

	// screenshot
	var (
		screenshotBytes []byte
		headlessBody    string
	)
	var pHash uint64
	if scanopts.Screenshot {
		var err error
		screenshotBytes, headlessBody, linkRequest, err = r.browser.ScreenshotWithBody(
			fullURL,
			scanopts.ScreenshotTimeout,
			scanopts.ScreenshotIdle,
			r.options.CustomHeaders,
			scanopts.IsScreenshotFullPage(),
			r.options.JavascriptCodes,
		)
		if err != nil {
			gologger.Warning().Msgf("Could not take screenshot '%s': %s", fullURL, err)
		} else {
			pHash, err = calculatePerceptionHash(screenshotBytes)
			if err != nil {
				gologger.Warning().Msgf("%v: %s", err, fullURL)
			}

			// As we now have headless body, we can also use it for detecting
			// more technologies in the response. This is a quick trick to get
			// more detected technologies.
			if r.options.TechDetect || r.options.JSONOutput || r.options.CSVOutput {
				moreMatches := r.wappalyzer.FingerprintWithInfo(resp.Headers, []byte(headlessBody))
				for match, data := range moreMatches {
					technologies = append(technologies, match)
					technologyDetails[match] = data
				}
				technologies = sliceutil.Dedupe(technologies)
			}
		}
		if scanopts.NoHeadlessBody {
			headlessBody = ""
		}
	}

	if scanopts.TechDetect && len(technologies) > 0 {
		sort.Strings(technologies)
		technologies := strings.Join(technologies, ",")
		// only print to console if tech-detect flag is enabled
		// scanopts.TechDetect implicitly enabled for json , csv and asset-upload
		if r.options.TechDetect {
			builder.WriteString(" [")
			if !scanopts.OutputWithNoColor {
				builder.WriteString(aurora.Magenta(technologies).String())
			} else {
				builder.WriteString(technologies)
			}
			builder.WriteRune(']')
		}
	}

	var cpeMatches []CPEInfo
	if r.cpeDetector != nil {
		cpeMatches = r.cpeDetector.Detect(title, string(resp.Data), faviconMMH3)
		if len(cpeMatches) > 0 && r.options.CPEDetect {
			for _, cpe := range cpeMatches {
				builder.WriteString(" [")
				if !scanopts.OutputWithNoColor {
					builder.WriteString(aurora.Cyan(cpe.CPE).String())
				} else {
					builder.WriteString(cpe.CPE)
				}
				builder.WriteRune(']')
			}
		}
	}

	var wpInfo *WordPressInfo
	if r.wpDetector != nil {
		wpInfo = r.wpDetector.Detect(string(resp.Data))
		if wpInfo.HasData() && r.options.WordPress {
			if len(wpInfo.Plugins) > 0 {
				builder.WriteString(" [")
				if !scanopts.OutputWithNoColor {
					builder.WriteString(aurora.Green("wp-plugins:" + strings.Join(wpInfo.Plugins, ",")).String())
				} else {
					builder.WriteString("wp-plugins:" + strings.Join(wpInfo.Plugins, ","))
				}
				builder.WriteRune(']')
			}
			if len(wpInfo.Themes) > 0 {
				builder.WriteString(" [")
				if !scanopts.OutputWithNoColor {
					builder.WriteString(aurora.Green("wp-themes:" + strings.Join(wpInfo.Themes, ",")).String())
				} else {
					builder.WriteString("wp-themes:" + strings.Join(wpInfo.Themes, ","))
				}
				builder.WriteRune(']')
			}
		}
	}

	result := Result{
		Timestamp:        time.Now(),
		Request:          request,
		LinkRequest:      linkRequest,
		ResponseHeaders:  responseHeaders,
		RawHeaders:       rawResponseHeaders,
		Scheme:           parsed.Scheme,
		Port:             finalPort,
		Path:             finalPath,
		Raw:              resp.Raw,
		URL:              fullURL,
		Input:            origInput,
		ContentLength:    resp.ContentLength,
		ChainStatusCodes: chainStatusCodes,
		Chain:            chainItems,
		StatusCode:       resp.StatusCode,
		Location:         resp.GetHeaderPart("Location", ";"),
		ContentType:      resp.GetHeaderPart("Content-Type", ";"),
		Title:            title,
		str:              builder.String(),
		VHost:            isvhost,
		WebServer:        serverHeader,
		ResponseBody:     serverResponseRaw,
		BodyPreview:      bodyPreview,
		WebSocket:        isWebSocket,
		TLSData:          resp.TLSData,
		CSPData:          resp.CSPData,
		Pipeline:         pipeline,
		HTTP2:            http2,
		Method:           method,
		Host:             parsed.Hostname(),
		HostIP:           ip,
		A:                ips4,
		AAAA:             ips6,
		CNAMEs:           cnames,
		CDN:              isCDN,
		CDNName:          cdnName,
		CDNType:          cdnType,
		ResponseTime:     resp.Duration.String(),
		Technologies:     technologies,
		FinalURL:         finalURL,
		FavIconMMH3:      faviconMMH3,
		FavIconMD5:       faviconMD5,
		FaviconPath:      faviconPath,
		FaviconURL:       faviconURL,
		Hashes:           hashesMap,
		Extracts:         extractResult,
		JarmHash:         jarmhash,
		Lines:            resp.Lines,
		Words:            resp.Words,
		ASN:              asnResponse,
		ExtractRegex:     extractRegex,
		ScreenshotBytes:  screenshotBytes,
		HeadlessBody:     headlessBody,
		KnowledgeBase: map[string]interface{}{
			"PageType": r.pageTypeClassifier.Classify(respData),
			"pHash":    pHash,
		},
		TechnologyDetails: technologyDetails,
		Resolvers:         resolvers,
		RequestRaw:        requestDump,
		Response:          resp,
		FaviconData:       faviconData,
		FileNameHash:      fileNameHash,
		CPE:               cpeMatches,
		WordPress:         wpInfo,
	}
	if resp.BodyDomains != nil {
		result.Fqdns = resp.BodyDomains.Fqdns
		result.Domains = resp.BodyDomains.Domains
	}
	if r.options.Trace {
		result.Trace = req.TraceInfo
	}
	return result
}

func (r *Runner) skip(URL *urlutil.URL, target httpx.Target, origInput string) (bool, Result) {
	if r.skipCDNPort(URL.Hostname(), URL.Port()) {
		gologger.Debug().Msgf("Skipping cdn target: %s:%s\n", URL.Host, URL.Port())
		return true, Result{URL: target.Host, Input: origInput, Err: errors.New("cdn target only allows ports 80 and 443")}
	}

	if !r.hp.NetworkPolicy.Validate(URL.Host) {
		gologger.Debug().Msgf("Skipping target due to network policy: %s\n", URL.Hostname())
		return true, Result{URL: target.Host, Input: origInput, Err: errors.New("target host is not allowed by network policy")}
	}

	return false, Result{}
}

func calculatePerceptionHash(screenshotBytes []byte) (uint64, error) {
	reader := bytes.NewReader(screenshotBytes)
	img, _, err := image.Decode(reader)
	if err != nil {
		return 0, errors.Wrap(err, "failed to decode screenshot")

	}

	pHash, err := goimagehash.PerceptionHash(img)
	if err != nil {
		return 0, errors.Wrap(err, "failed to calculate perceptual hash")
	}

	return pHash.GetHash(), nil
}

func (r *Runner) HandleFaviconHash(hp *httpx.HTTPX, req *retryablehttp.Request, currentResp []byte, finalURL string, defaultProbe bool) (string, string, string, []byte, string, error) {
	// Check if current URI is ending with .ico => use current body without additional requests
	if path.Ext(req.Path) == ".ico" {
		mmh3, md5h, err := r.calculateFaviconHashWithRaw(currentResp)
		return mmh3, md5h, req.Path, currentResp, req.String(), err
	}

	// Parse HTML: collect <link rel="...icon..."> hrefs + optional <base href>
	hrefs, baseHref, err := extractPotentialFavIconsURLs(currentResp)
	if err != nil {
		return "", "", "", nil, "", err
	}

	// If none found and probing allowed, add default /favicon.ico
	if len(hrefs) == 0 && defaultProbe {
		hrefs = append(hrefs, "/favicon.ico")
	}

	// Determine base URL: prefer finalURL (redirect target) then apply <base href>
	baseNet, _ := url.Parse(req.String())
	if finalURL != "" {
		if u, err := url.Parse(finalURL); err == nil {
			baseNet = u
		}
	}
	if baseHref != "" {
		if bu, err := url.Parse(baseHref); err == nil {
			baseNet = baseNet.ResolveReference(bu)
		}
	}

	// Clone original request (reuse headers/cookies)
	clone := req.Clone(context.Background())

	var (
		faviconMMH3 string
		faviconMD5  string
		faviconPath string
		faviconURL  string
		faviconData []byte
		tries       int // network fetch attempts
	)

	// Iterate candidates (.ico first ordering handled in extractPotentialFavIconsURLs)
	for _, raw := range hrefs {
		if tries == 2 {
			break
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		// data: URL (base64) favicon
		if stringz.IsBase64Icon(raw) {
			data, err := stringz.DecodeBase64Icon(raw)
			if err != nil {
				continue
			}
			mmh3, md5h, err := r.calculateFaviconHashWithRaw(data)
			if err != nil {
				continue
			}
			return mmh3, md5h, "data:", data, "", nil
		}

		// Resolve relative/absolute href
		parsedHref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		resolvedNet := baseNet.ResolveReference(parsedHref)
		resolvedURL, err := urlutil.ParseURL(resolvedNet.String(), r.options.Unsafe)
		if err != nil {
			continue
		}

		clone.SetURL(resolvedURL)
		// Update Host header to match resolved URL host (important after redirects)
		if resolvedURL.Host != "" && resolvedURL.Host != clone.Host {
			clone.Host = resolvedURL.Host
		}
		respFav, err := hp.Do(clone, httpx.UnsafeOptions{})
		if err != nil || len(respFav.Data) == 0 {
			tries++
			// Root fallback: directory-relative failed and raw had no leading slash
			if !strings.HasPrefix(raw, "/") {
				rootResolvedNet := baseNet.ResolveReference(&url.URL{Path: "/" + raw})
				rootResolvedURL, err2 := urlutil.ParseURL(rootResolvedNet.String(), r.options.Unsafe)
				if err2 != nil {
					continue
				}
				clone.SetURL(rootResolvedURL)
				if respFav2, err3 := hp.Do(clone, httpx.UnsafeOptions{}); err3 == nil && len(respFav2.Data) > 0 {
					respFav = respFav2
				} else {
					continue
				}
			} else {
				continue
			}
		}

		// Hash favicon bytes
		mmh3, md5h, err := r.calculateFaviconHashWithRaw(respFav.Data)
		if err != nil {
			continue
		}
		faviconMMH3 = mmh3
		faviconMD5 = md5h
		faviconPath = raw
		faviconURL = clone.String()
		faviconData = respFav.Data
		gologger.Debug().Msgf("favicon resolved url=%s raw_href=%s size=%d bytes", faviconURL, faviconPath, len(faviconData))
		break
	}

	return faviconMMH3, faviconMD5, faviconPath, faviconData, faviconURL, nil
}

func (r *Runner) calculateFaviconHashWithRaw(data []byte) (string, string, error) {
	hashNum, md5Hash, err := stringz.FaviconHash(data)
	if err != nil {
		return "", "", errkit.Wrapf(err, "could not calculate favicon hash")
	}
	return fmt.Sprintf("%d", hashNum), md5Hash, nil
}

func extractPotentialFavIconsURLs(resp []byte) (candidates []string, baseHref string, err error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp))
	if err != nil {
		return nil, "", err
	}

	if b := doc.Find("base[href]").First(); b.Length() == 1 {
		if v, ok := b.Attr("href"); ok {
			baseHref = strings.TrimSpace(v)
		}
	}

	doc.Find("link[rel]").Each(func(_ int, s *goquery.Selection) {
		rel := strings.ToLower(strings.TrimSpace(s.AttrOr("rel", "")))
		href := strings.TrimSpace(s.AttrOr("href", ""))
		if href == "" {
			return
		}
		for _, tok := range strings.Fields(rel) {
			switch tok {
			case "icon", "shortcut", "shortcut-icon", "apple-touch-icon", "mask-icon", "alternate":
				candidates = append(candidates, href)
				return
			}
		}
	})

	sort.SliceStable(candidates, func(i, j int) bool {
		ai := strings.HasSuffix(strings.ToLower(candidates[i]), ".ico")
		aj := strings.HasSuffix(strings.ToLower(candidates[j]), ".ico")
		if ai == aj {
			return candidates[i] < candidates[j]
		}
		return ai && !aj
	})

	return candidates, baseHref, nil
}

// SaveResumeConfig to file
func (r *Runner) SaveResumeConfig() error {
	var resumeCfg ResumeCfg
	resumeCfg.Index = r.options.resumeCfg.currentIndex
	resumeCfg.ResumeFrom = r.options.resumeCfg.current
	return goconfig.Save(resumeCfg, DefaultResumeFile)
}

// JSON the result
func (r Result) JSON(scanopts *ScanOptions) string { //nolint
	if scanopts != nil && len(r.ResponseBody) > scanopts.MaxResponseBodySizeToSave {
		r.ResponseBody = r.ResponseBody[:scanopts.MaxResponseBodySizeToSave]
	}

	if js, err := json.Marshal(r); err == nil {
		return string(js)
	}

	return ""
}

// CSVHeader the CSV headers
func (r Result) CSVHeader() string { //nolint
	var header string

	if h, err := gocsv.MarshalString([]Result{}); err == nil {
		header = h
	}
	header = strings.TrimSpace(header)

	return header
}

// CSVRow the CSV Row
func (r Result) CSVRow(scanopts *ScanOptions) string { //nolint
	var res string

	if scanopts != nil && len(r.ResponseBody) > scanopts.MaxResponseBodySizeToSave {
		r.ResponseBody = r.ResponseBody[:scanopts.MaxResponseBodySizeToSave]
	}

	if row, err := gocsv.MarshalStringWithoutHeaders([]Result{r}); err == nil {
		reader := csv.NewReader(strings.NewReader(row))
		records, err := reader.ReadAll()
		if err == nil && len(records) > 0 {
			buf := &bytes.Buffer{}
			writer := csv.NewWriter(buf)
			for _, record := range records {
				for i, field := range record {
					if len(field) > 0 {
						firstChar := field[0]
						// NOTE(dwisiswant0): Sanitize (prevent CSV injection).
						if firstChar == '=' || firstChar == '+' || firstChar == '-' || firstChar == '@' {
							record[i] = "'" + field
						}
					}
				}
				_ = writer.Write(record) //nolint
			}
			writer.Flush()
			res = buf.String()
		} else {
			res = row
		}
		res = strings.TrimSpace(res)
	}

	return res
}

func (r *Runner) skipCDNPort(host string, port string) bool {
	// if the option is not enabled we don't skip
	if !r.scanopts.ExcludeCDN {
		return false
	}
	// uses the dealer to pre-resolve the target
	dnsData, err := r.hp.Dialer.GetDNSData(host)
	// if we get an error the target cannot be resolved, so we return false so that the program logic continues as usual and handles the errors accordingly
	if err != nil {
		return false
	}

	if len(dnsData.A) == 0 {
		return false
	}

	// pick the first ip as target
	hostIP := dnsData.A[0]

	isCdnIP, _, _, err := r.hp.CdnCheck(hostIP)
	if err != nil {
		return false
	}

	if isCdnIP && slices.Contains(r.options.CustomPorts, port) {
		return true
	}
	// If the target is part of the CDN ips range - only ports 80 and 443 are allowed
	if isCdnIP && port != "80" && port != "443" {
		return true
	}

	return false
}

// parseURL parses url based on cli option(unsafe)
func (r *Runner) parseURL(url string) (*urlutil.URL, error) {
	urlx, err := urlutil.ParseURL(url, r.options.Unsafe)
	if err != nil {
		gologger.Debug().Msgf("failed to parse url %v got %v in unsafe:%v", url, err, r.options.Unsafe)
	}
	return urlx, err
}

func getDNSData(hp *httpx.HTTPX, hostname string) (ips, cnames, resolvers []string, err error) {
	dnsData, err := hp.Dialer.GetDNSData(hostname)
	if err != nil {
		return nil, nil, nil, err
	}
	ips = make([]string, 0, len(dnsData.A)+len(dnsData.AAAA))
	ips = append(ips, dnsData.A...)
	ips = append(ips, dnsData.AAAA...)
	cnames = dnsData.CNAME
	resolvers = append(resolvers, dnsData.Resolver...)
	return
}

func normalizeHeaders(headers map[string][]string) map[string]interface{} {
	normalized := make(map[string]interface{}, len(headers))
	for k, v := range headers {
		normalized[strings.ReplaceAll(strings.ToLower(k), "-", "_")] = strings.Join(v, ", ")
	}
	return normalized
}

func isWebSocket(resp *httpx.Response) bool {
	if resp.StatusCode == 101 {
		return true
	}
	// TODO: improve this checks
	// Check for specific headers that indicate WebSocket support
	keyHeaders := []string{`^Sec-WebSocket-Accept:\s+.+`, `^Upgrade:\s+websocket`, `^Connection:\s+upgrade`}
	for _, header := range keyHeaders {
		re := regexp.MustCompile(header)
		if re.MatchString(resp.RawHeaders) {
			return true
		}
	}
	// Check for specific data that indicates WebSocket support
	keyData := []string{`{"socket":true,"socketUrl":"(?:wss?|ws)://.*"}`, `{"sid":"[^"]*","upgrades":\["websocket"\].*}`}
	for _, data := range keyData {
		re := regexp.MustCompile(data)
		if re.Match(resp.RawData) {
			return true
		}
	}
	return false
}

// stripANSI removes ANSI color codes from a string using pre-compiled regex
func stripANSI(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}
