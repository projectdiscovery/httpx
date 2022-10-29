package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/maps"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	dsl "github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/httpx/common/customextract"
	"github.com/projectdiscovery/httpx/common/hashes/jarm"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/mapsutil"

	"github.com/bluele/gcache"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/httpx/common/hashes"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/sliceutil"
	"github.com/projectdiscovery/stringsutil"
	"github.com/projectdiscovery/urlutil"

	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"

	// automatic fd max increase if running as root
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	pdhttputil "github.com/projectdiscovery/httputil"
	customport "github.com/projectdiscovery/httpx/common/customports"
	fileutilz "github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/httputilz"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/slice"
	"github.com/projectdiscovery/httpx/common/stringz"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/rawhttp"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	options         *Options
	hp              *httpx.HTTPX
	wappalyzer      *wappalyzer.Wappalyze
	fastdialer      *fastdialer.Dialer
	scanopts        scanOptions
	hm              *hybrid.HybridMap
	stats           clistats.StatisticsClient
	ratelimiter     ratelimit.Limiter
	HostErrorsCache gcache.Cache
	asnClinet       asn.ASNClient
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options:   options,
		asnClinet: asn.New(),
	}
	var err error
	if options.TechDetect {
		runner.wappalyzer, err = wappalyzer.New()
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create wappalyzer client")
	}

	dialerOpts := fastdialer.DefaultOptions
	dialerOpts.WithDialerHistory = true
	dialerOpts.MaxRetries = 3
	dialerOpts.DialerTimeout = time.Duration(options.Timeout) * time.Second
	if len(options.Resolvers) > 0 {
		dialerOpts.BaseResolvers = options.Resolvers
	}
	fastDialer, err := fastdialer.NewDialer(dialerOpts)
	if err != nil {
		return nil, errors.Wrap(err, "could not create dialer")
	}
	runner.fastdialer = fastDialer

	httpxOptions := httpx.DefaultOptions
	// Enables automatically tlsgrab if tlsprobe is requested
	httpxOptions.TLSGrab = options.TLSGrab || options.TLSProbe
	httpxOptions.Timeout = time.Duration(options.Timeout) * time.Second
	httpxOptions.RetryMax = options.Retries
	httpxOptions.FollowRedirects = options.FollowRedirects
	httpxOptions.FollowHostRedirects = options.FollowHostRedirects
	httpxOptions.MaxRedirects = options.MaxRedirects
	httpxOptions.HTTPProxy = options.HTTPProxy
	httpxOptions.Unsafe = options.Unsafe
	httpxOptions.UnsafeURI = options.RequestURI
	httpxOptions.CdnCheck = options.OutputCDN
	httpxOptions.ExcludeCdn = options.ExcludeCDN
	if options.CustomHeaders.Has("User-Agent:") {
		httpxOptions.RandomAgent = false
	} else {
		httpxOptions.RandomAgent = options.RandomAgent
	}
	httpxOptions.Deny = options.Deny
	httpxOptions.Allow = options.Allow
	httpxOptions.MaxResponseBodySizeToSave = int64(options.MaxResponseBodySizeToSave)
	httpxOptions.MaxResponseBodySizeToRead = int64(options.MaxResponseBodySizeToRead)
	// adjust response size saved according to the max one read by the server
	if httpxOptions.MaxResponseBodySizeToSave > httpxOptions.MaxResponseBodySizeToRead {
		httpxOptions.MaxResponseBodySizeToSave = httpxOptions.MaxResponseBodySizeToRead
	}
	httpxOptions.Resolvers = options.Resolvers

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

	var scanopts scanOptions

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
	scanopts.OutputWithNoColor = options.NoColor
	scanopts.ResponseInStdout = options.responseInStdout
	scanopts.ChainInStdout = options.chainInStdout
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
	scanopts.TechDetect = options.TechDetect
	scanopts.StoreChain = options.StoreChain
	scanopts.MaxResponseBodySizeToSave = options.MaxResponseBodySizeToSave
	scanopts.MaxResponseBodySizeToRead = options.MaxResponseBodySizeToRead
	scanopts.extractRegexps = make(map[string]*regexp.Regexp)

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

	scanopts.ExcludeCDN = options.ExcludeCDN
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

	hmapOptions := hybrid.DefaultDiskOptions
	hmapOptions.DBType = hybrid.PogrebDB
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}
	runner.hm = hm

	if options.RateLimitMinute > 0 {
		runner.ratelimiter = *ratelimit.New(context.Background(), int64(options.RateLimitMinute), time.Minute)
	} else if options.RateLimit > 0 {
		runner.ratelimiter = *ratelimit.New(context.Background(), int64(options.RateLimit), time.Second)
	} else {
		runner.ratelimiter = *ratelimit.NewUnlimited(context.Background())
	}

	if options.HostMaxErrors >= 0 {
		gc := gcache.New(1000).
			ARC().
			Build()
		runner.HostErrorsCache = gc
	}

	return runner, nil
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

func (r *Runner) prepareInput() {
	var numHosts int
	// check if input target host(s) have been provided
	if len(r.options.InputTargetHost) > 0 {
		for _, target := range r.options.InputTargetHost {
			expandedTarget := r.countTargetFromRawTarget(target)
			if expandedTarget > 0 {
				numHosts += expandedTarget
				r.hm.Set(target, nil) //nolint
			}
		}
	}
	// check if file has been provided
	if fileutil.FileExists(r.options.InputFile) {
		finput, err := os.Open(r.options.InputFile)
		if err != nil {
			gologger.Fatal().Msgf("Could not read input file '%s': %s\n", r.options.InputFile, err)
		}
		numHosts, err = r.loadAndCloseFile(finput)
		if err != nil {
			gologger.Fatal().Msgf("Could not read input file '%s': %s\n", r.options.InputFile, err)
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
	if fileutil.HasStdin() {
		numTargetsStdin, err := r.loadAndCloseFile(os.Stdin)
		if err != nil {
			gologger.Fatal().Msgf("Could not read input from stdin: %s\n", err)
		}
		numHosts += numTargetsStdin
	}

	if r.options.ShowStatistics {
		r.stats.AddStatic("totalHosts", numHosts)
		r.stats.AddCounter("hosts", 0)
		r.stats.AddStatic("startedAt", time.Now())
		r.stats.AddCounter("requests", 0)

		err := r.stats.Start(makePrintCallback(), time.Duration(r.options.StatsInterval)*time.Second)
		if err != nil {
			gologger.Warning().Msgf("Could not create statistics: %s\n", err)
		}
	}
}

func (r *Runner) setSeen(k string) {
	_ = r.hm.Set(k, nil)
}

func (r *Runner) seen(k string) bool {
	_, ok := r.hm.Get(k)
	return ok
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

func (r *Runner) streamInput() (chan string, error) {
	out := make(chan string)
	go func() {
		defer close(out)

		if fileutil.FileExists(r.options.InputFile) {
			fchan, err := fileutil.ReadFile(r.options.InputFile)
			if err != nil {
				return
			}
			for item := range fchan {
				if r.options.SkipDedupe || r.testAndSet(item) {
					out <- item
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
		expandedTarget := r.countTargetFromRawTarget(target)
		if expandedTarget > 0 {
			numTargets += expandedTarget
			r.hm.Set(target, nil) //nolint
		}
	}
	err = finput.Close()
	return numTargets, err
}

func (r *Runner) countTargetFromRawTarget(rawTarget string) (numTargets int) {
	if rawTarget == "" {
		return 0
	}
	if _, ok := r.hm.Get(rawTarget); ok {
		return 0
	}

	expandedTarget := 0
	switch {
	case iputil.IsCIDR(rawTarget):
		if ipsCount, err := mapcidr.AddressCount(rawTarget); err == nil && ipsCount > 0 {
			expandedTarget = int(ipsCount)
		}
	case asn.IsASN(rawTarget):
		asn := asn.New()
		cidrs, _ := asn.GetCIDRsForASNNum(rawTarget)
		for _, cidr := range cidrs {
			expandedTarget += int(mapcidr.AddressCountIpnet(cidr))
		}
	default:
		expandedTarget = 1
	}
	return expandedTarget
}

var (
	lastRequestsCount float64
)

func makePrintCallback() func(stats clistats.StatisticsClient) {
	builder := &strings.Builder{}
	return func(stats clistats.StatisticsClient) {
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
		builder.WriteString(fmt.Sprintf("%.0f", currentRequests))

		hosts, _ := stats.GetCounter("hosts")
		totalHosts, _ := stats.GetStatic("totalHosts")

		builder.WriteString(" | Hosts: ")
		builder.WriteString(clistats.String(hosts))
		builder.WriteRune('/')
		builder.WriteString(clistats.String(totalHosts))
		builder.WriteRune(' ')
		builder.WriteRune('(')
		//nolint:gomnd // this is not a magic number
		builder.WriteString(clistats.String(uint64(float64(hosts) / float64(totalHosts.(int)) * 100.0)))
		builder.WriteRune('%')
		builder.WriteRune(')')

		builder.WriteRune('\n')

		fmt.Fprintf(os.Stderr, "%s", builder.String())
		builder.Reset()

		lastRequestsCount = currentRequests
	}
}

// Close closes the httpx scan instance
func (r *Runner) Close() {
	// nolint:errcheck // ignore
	r.hm.Close()
	r.hp.Dialer.Close()
	if r.options.HostMaxErrors >= 0 {
		r.HostErrorsCache.Purge()
	}
}

// RunEnumeration on targets for httpx client
func (r *Runner) RunEnumeration() {
	// Try to create output folder if it doesn't exist
	if r.options.StoreResponse && !fileutil.FolderExists(r.options.StoreResponseDir) {
		if err := os.MkdirAll(r.options.StoreResponseDir, os.ModePerm); err != nil {
			gologger.Fatal().Msgf("Could not create output directory '%s': %s\n", r.options.StoreResponseDir, err)
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
	wgoutput := sizedwaitgroup.New(1)
	wgoutput.Add()
	output := make(chan Result)
	go func(output chan Result) {
		defer wgoutput.Done()

		var f *os.File
		if r.options.Output != "" {
			var err error
			if r.options.Resume {
				f, err = os.OpenFile(r.options.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			} else {
				f, err = os.Create(r.options.Output)
			}
			if err != nil {
				gologger.Fatal().Msgf("Could not create output file '%s': %s\n", r.options.Output, err)
			}
			defer f.Close() //nolint
		}
		if r.options.CSVOutput {
			header := Result{}.CSVHeader()
			gologger.Silent().Msgf("%s\n", header)
			if f != nil {
				//nolint:errcheck // this method needs a small refactor to reduce complexity
				f.WriteString(header + "\n")
			}
		}

		for resp := range output {
			if resp.err != nil {
				// Change the error message if any port value passed explicitly
				if url, err := url.Parse(resp.URL); err == nil && url.Port() != "" {
					resp.err = errors.New(strings.ReplaceAll(resp.err.Error(), "address", "port"))
				}
				gologger.Debug().Msgf("Failed '%s': %s\n", resp.URL, resp.err)
			}
			if resp.str == "" {
				continue
			}

			// apply matchers and filters
			if r.options.OutputFilterCondition != "" || r.options.OutputMatchCondition != "" {
				rawMap, err := ResultToMap(resp)
				if err != nil {
					gologger.Warning().Msgf("Could not decode response: %s\n", err)
					continue
				}

				flatMap := make(map[string]any)
				mapsutil.Walk(rawMap, func(k string, v any) {
					flatMap[k] = v
				})

				if r.options.OutputMatchCondition != "" {
					res, err := dsl.EvalExpr(r.options.OutputMatchCondition, flatMap)
					if err != nil {
						gologger.Error().Msgf("Could not evaluate match condition: %s\n", err)
						continue
					} else {
						if res == false {
							continue
						}
					}
				}
				if r.options.OutputFilterCondition != "" {
					res, err := dsl.EvalExpr(r.options.OutputFilterCondition, flatMap)
					if err != nil {
						gologger.Error().Msgf("Could not evaluate filter condition: %s\n", err)
						continue
					} else {
						if res == true {
							continue
						}
					}
				}
			}

			if len(r.options.filterStatusCode) > 0 && slice.IntSliceContains(r.options.filterStatusCode, resp.StatusCode) {
				continue
			}
			if len(r.options.filterContentLength) > 0 && slice.IntSliceContains(r.options.filterContentLength, resp.ContentLength) {
				continue
			}
			if len(r.options.filterLinesCount) > 0 && slice.IntSliceContains(r.options.filterLinesCount, resp.Lines) {
				continue
			}
			if len(r.options.filterWordsCount) > 0 && slice.IntSliceContains(r.options.filterWordsCount, resp.Words) {
				continue
			}
			if r.options.filterRegex != nil && r.options.filterRegex.MatchString(resp.raw) {
				continue
			}
			if r.options.OutputFilterString != "" && strings.Contains(strings.ToLower(resp.raw), strings.ToLower(r.options.OutputFilterString)) {
				continue
			}
			if len(r.options.OutputFilterFavicon) > 0 && stringsutil.EqualFoldAny(resp.FavIconMMH3, r.options.OutputFilterFavicon...) {
				continue
			}
			if len(r.options.matchStatusCode) > 0 && !slice.IntSliceContains(r.options.matchStatusCode, resp.StatusCode) {
				continue
			}
			if len(r.options.matchContentLength) > 0 && !slice.IntSliceContains(r.options.matchContentLength, resp.ContentLength) {
				continue
			}
			if r.options.matchRegex != nil && !r.options.matchRegex.MatchString(resp.raw) {
				continue
			}
			if r.options.OutputMatchString != "" && !strings.Contains(strings.ToLower(resp.raw), strings.ToLower(r.options.OutputMatchString)) {
				continue
			}
			if len(r.options.OutputMatchFavicon) > 0 && !stringsutil.EqualFoldAny(resp.FavIconMMH3, r.options.OutputMatchFavicon...) {
				continue
			}
			if len(r.options.matchLinesCount) > 0 && !slice.IntSliceContains(r.options.matchLinesCount, resp.Lines) {
				continue
			}
			if len(r.options.matchWordsCount) > 0 && !slice.IntSliceContains(r.options.matchWordsCount, resp.Words) {
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
			row := resp.str
			if r.options.JSONOutput {
				row = resp.JSON(&r.scanopts)
			} else if r.options.CSVOutput {
				row = resp.CSVRow(&r.scanopts)
			}

			gologger.Silent().Msgf("%s\n", row)
			if f != nil {
				//nolint:errcheck // this method needs a small refactor to reduce complexity
				f.WriteString(row + "\n")
			}
		}
	}(output)

	wg := sizedwaitgroup.New(r.options.Threads)

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
		if u, err := url.Parse(k); err == nil {
			if r.options.NoFallbackScheme && u.Scheme == httpx.HTTP || u.Scheme == httpx.HTTPS {
				protocol = u.Scheme
			}
		}

		if len(r.options.requestURIs) > 0 {
			for _, p := range r.options.requestURIs {
				scanopts := r.scanopts.Clone()
				scanopts.RequestURI = p
				r.process(k, &wg, r.hp, protocol, scanopts, output)
			}
		} else {
			r.process(k, &wg, r.hp, protocol, &r.scanopts, output)
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
}

func (r *Runner) GetScanOpts() scanOptions {
	return r.scanopts
}

func (r *Runner) Process(t string, wg *sizedwaitgroup.SizedWaitGroup, protocol string, scanopts *scanOptions, output chan Result) {
	r.process(t, wg, r.hp, protocol, scanopts, output)
}

func (r *Runner) process(t string, wg *sizedwaitgroup.SizedWaitGroup, hp *httpx.HTTPX, protocol string, scanopts *scanOptions, output chan Result) {
	protocols := []string{protocol}
	if scanopts.NoFallback || protocol == httpx.HTTPandHTTPS {
		protocols = []string{httpx.HTTPS, httpx.HTTP}
	}

	for target := range r.targets(hp, stringz.TrimProtocol(t, scanopts.NoFallback || scanopts.NoFallbackScheme)) {
		// if no custom ports specified then test the default ones
		if len(customport.Ports) == 0 {
			for _, method := range scanopts.Methods {
				for _, prot := range protocols {
					wg.Add()
					go func(target httpx.Target, method, protocol string) {
						defer wg.Done()
						result := r.analyze(hp, protocol, target, method, t, scanopts)
						output <- result
						if scanopts.TLSProbe && result.TLSData != nil {
							scanopts.TLSProbe = false
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
							for _, tt := range result.CSPData.Domains {
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
			wantedProtocols := []string{wantedProtocolForPort}
			if wantedProtocolForPort == httpx.HTTPandHTTPS {
				wantedProtocols = []string{httpx.HTTPS, httpx.HTTP}
			}
			for _, wantedProtocol := range wantedProtocols {
				for _, method := range scanopts.Methods {
					wg.Add()
					go func(port int, target httpx.Target, method, protocol string) {
						defer wg.Done()
						target.Host, _ = urlutil.ChangePort(target.Host, fmt.Sprint(port))
						result := r.analyze(hp, protocol, target, method, t, scanopts)
						output <- result
						if scanopts.TLSProbe && result.TLSData != nil {
							scanopts.TLSProbe = false
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
		switch {
		case strings.ContainsAny(target, "*") || strings.HasPrefix(target, "."):
			// A valid target does not contain:
			// *
			// spaces
			// trim * and/or . (prefix) from the target to return the domain instead of wilcard
			target = strings.TrimPrefix(strings.Trim(target, "*"), ".")
			if !r.testAndSet(target) {
				return
			}
			results <- httpx.Target{Host: target}
		case asn.IsASN(target):
			cidrIps, err := r.asnClinet.GetIPAddressesAsStream(target)
			if err != nil {
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
			URL, err := urlutil.Parse(target)
			if err != nil {
				results <- httpx.Target{Host: target}
			}
			ips, _, err := getDNSData(hp, URL.Host)
			if err != nil || len(ips) == 0 {
				results <- httpx.Target{Host: target}
			}
			for _, ip := range ips {
				results <- httpx.Target{Host: target, CustomIP: ip}
			}
		case strings.Index(target, ",") > 0:
			idxComma := strings.Index(target, ",")
			results <- httpx.Target{Host: target[idxComma+1:], CustomHost: target[:idxComma]}
		default:
			results <- httpx.Target{Host: target}
		}
	}()
	return results
}

func (r *Runner) analyze(hp *httpx.HTTPX, protocol string, target httpx.Target, method, origInput string, scanopts *scanOptions) Result {
	origProtocol := protocol
	if protocol == httpx.HTTPorHTTPS || protocol == httpx.HTTPandHTTPS {
		protocol = httpx.HTTPS
	}
	retried := false
retry:
	if scanopts.VHostInput && target.CustomHost == "" {
		return Result{Input: origInput}
	}
	URL, err := urlutil.Parse(target.Host)
	if err != nil {
		return Result{URL: target.Host, Input: origInput, err: err}
	}

	// check if we have to skip the host:port as a result of a previous failure
	hostPort := net.JoinHostPort(URL.Host, URL.Port)
	if r.options.HostMaxErrors >= 0 && r.HostErrorsCache.Has(hostPort) {
		numberOfErrors, err := r.HostErrorsCache.GetIFPresent(hostPort)
		if err == nil && numberOfErrors.(int) >= r.options.HostMaxErrors {
			return Result{URL: target.Host, err: errors.New("skipping as previously unresponsive")}
		}
	}

	// check if the combination host:port should be skipped if belonging to a cdn
	if r.skipCDNPort(URL.Host, URL.Port) {
		gologger.Debug().Msgf("Skipping cdn target: %s:%s\n", URL.Host, URL.Port)
		return Result{URL: target.Host, Input: origInput, err: errors.New("cdn target only allows ports 80 and 443")}
	}

	URL.Scheme = protocol

	if !strings.Contains(target.Host, URL.Port) {
		URL.Port = ""
	}

	var reqURI string
	// retry with unsafe
	if scanopts.Unsafe {
		reqURI = URL.RequestURI + scanopts.RequestURI
		// then create a base request without it to avoid go errors
		URL.RequestURI = ""
	} else {
		// in case of standard requests append the new path to the existing one
		URL.RequestURI += scanopts.RequestURI
	}
	var req *retryablehttp.Request
	if target.CustomIP != "" {
		var requestIP string
		if iputil.IsIPv6(target.CustomIP) {
			requestIP = fmt.Sprintf("[%s]", target.CustomIP)
		} else {
			requestIP = target.CustomIP
		}
		ctx := context.WithValue(context.Background(), "ip", requestIP) //nolint
		req, err = hp.NewRequestWithContext(ctx, method, URL.String())
	} else {
		req, err = hp.NewRequest(method, URL.String())
	}
	if err != nil {
		return Result{URL: URL.String(), Input: origInput, err: err}
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
		requestDump, errDump = rawhttp.DumpRequestRaw(req.Method, req.URL.String(), reqURI, req.Header, req.Body, rawhttp.DefaultOptions)
		if errDump != nil {
			return Result{URL: URL.String(), Input: origInput, err: errDump}
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
			return Result{URL: URL.String(), Input: origInput, err: errDump}
		}
		// The original req.Body gets modified indirectly by httputil.DumpRequestOut so we set it again to nil if it was empty
		// Otherwise redirects like 307/308 would fail (as they require the body to be sent along)
		if len(scanopts.RequestBody) == 0 {
			req.ContentLength = 0
			req.Body = nil
		}
	}
	// fix the final output url
	fullURL := req.URL.String()
	if parsedURL, errParse := urlutil.Parse(fullURL); errParse != nil {
		return Result{URL: URL.String(), Input: origInput, err: errParse}
	} else {
		if r.options.Unsafe {
			parsedURL.RequestURI = reqURI
			// if the full url doesn't end with the custom path we pick the original input value
		} else if !stringsutil.HasSuffixAny(fullURL, scanopts.RequestURI) {
			parsedURL.RequestURI = scanopts.RequestURI
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
	builder.WriteString(stringz.RemoveURLDefaultPort(fullURL))

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
			if protocol == httpx.HTTPS {
				protocol = httpx.HTTP
			} else {
				protocol = httpx.HTTPS
			}
			retried = true
			goto retry
		}

		// mark the host:port as failed to avoid further checks
		if r.options.HostMaxErrors >= 0 {
			errorCount, err := r.HostErrorsCache.GetIFPresent(hostPort)
			if err != nil || errorCount == nil {
				_ = r.HostErrorsCache.Set(hostPort, 1)
			} else if errorCount != nil {
				_ = r.HostErrorsCache.Set(hostPort, errorCount.(int)+1)
			}
		}

		if r.options.Probe {
			return Result{URL: URL.String(), Input: origInput, Timestamp: time.Now(), err: err, Failed: err != nil, Error: errString, str: builder.String()}
		} else {
			return Result{URL: URL.String(), Input: origInput, Timestamp: time.Now(), err: err}
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

	title := httpx.ExtractTitle(resp)
	if scanopts.OutputTitle {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Cyan(title).String())
		} else {
			builder.WriteString(title)
		}
		builder.WriteRune(']')
	}

	serverHeader := resp.GetHeader("Server")
	if scanopts.OutputServerHeader {
		builder.WriteString(fmt.Sprintf(" [%s]", serverHeader))
	}

	var serverResponseRaw string
	var request string
	var rawResponseHeader string
	var responseHeader map[string]interface{}
	if scanopts.ResponseInStdout {
		serverResponseRaw = string(resp.Data)
		request = string(requestDump)
		responseHeader = normalizeHeaders(resp.Headers)
		rawResponseHeader = resp.RawHeaders
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
	isWebSocket := resp.StatusCode == 101
	if scanopts.OutputWebSocket && isWebSocket {
		builder.WriteString(" [websocket]")
	}

	pipeline := false
	if scanopts.Pipeline {
		port, _ := strconv.Atoi(URL.Port)
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
		// hp.Dialer.GetDialedIP would return only the last dialed one
		ip = hp.Dialer.GetDialedIP(URL.Host)
	}

	var asnResponse *AsnResponse
	if r.options.Asn {
		results := asnmap.NewClient().GetData(asnmap.IP(ip))
		if len(results) > 0 {
			var cidrs []string
			for _, cidr := range asnmap.GetCIDR(results) {
				cidrs = append(cidrs, cidr.String())
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
		builder.WriteString(fmt.Sprintf(" [%s]", ip))
	}

	ips, cnames, err := getDNSData(hp, URL.Host)
	if err != nil {
		ips = append(ips, ip)
	}

	if scanopts.OutputCName && len(cnames) > 0 {
		// Print only the first CNAME (full list in json)
		builder.WriteString(fmt.Sprintf(" [%s]", cnames[0]))
	}

	isCDN, cdnName, err := hp.CdnCheck(ip)
	if scanopts.OutputCDN && isCDN && err == nil {
		builder.WriteString(fmt.Sprintf(" [%s]", cdnName))
	}

	if scanopts.OutputResponseTime {
		builder.WriteString(fmt.Sprintf(" [%s]", resp.Duration))
	}

	var technologies []string
	if scanopts.TechDetect {
		matches := r.wappalyzer.Fingerprint(resp.Headers, resp.Data)
		for match := range matches {
			technologies = append(technologies, match)
		}

		if len(technologies) > 0 {
			sort.Strings(technologies)
			technologies := strings.Join(technologies, ",")

			builder.WriteString(" [")
			if !scanopts.OutputWithNoColor {
				builder.WriteString(aurora.Magenta(technologies).String())
			} else {
				builder.WriteString(technologies)
			}
			builder.WriteRune(']')
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
		finalURL = resp.GetChainLastURL()
	}

	if resp.HasChain() {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(finalURL).String())
		} else {
			builder.WriteString(finalURL)
		}
		builder.WriteRune(']')
	}
	var faviconMMH3 string
	if scanopts.Favicon {
		req.URL.Path = "/favicon.ico"
		if faviconResp, favErr := hp.Do(req, httpx.UnsafeOptions{}); favErr == nil {
			faviconMMH3 = fmt.Sprintf("%d", stringz.FaviconHash(faviconResp.Data))
			builder.WriteString(" [")
			if !scanopts.OutputWithNoColor {
				builder.WriteString(aurora.Magenta(faviconMMH3).String())
			} else {
				builder.WriteString(faviconMMH3)
			}
			builder.WriteRune(']')
		} else {
			gologger.Warning().Msgf("Could not fetch favicon: %s", favErr.Error())
		}
	}
	// adding default hashing for json output format
	if r.options.JSONOutput && len(scanopts.Hashes) == 0 {
		scanopts.Hashes = "md5,mmh3,sha256,simhash"
	}
	hashesMap := make(map[string]interface{})
	if scanopts.Hashes != "" {
		hs := strings.Split(scanopts.Hashes, ",")
		builder.WriteString(" [")
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
		builder.WriteRune(']')
	}
	if scanopts.OutputLinesCount {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(resp.Lines).String())
		} else {
			builder.WriteString(fmt.Sprint(resp.Lines))
		}
		builder.WriteRune(']')
	}
	jarmhash := ""
	if r.options.Jarm {
		jarmhash = jarm.Jarm(r.fastdialer, fullURL, r.options.Timeout)
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(jarmhash).String())
		} else {
			builder.WriteString(fmt.Sprint(jarmhash))
		}
		builder.WriteRune(']')
	}
	if scanopts.OutputWordsCount {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(resp.Words).String())
		} else {
			builder.WriteString(fmt.Sprint(resp.Words))
		}
		builder.WriteRune(']')
	}

	// store responses or chain in directory
	var responsePath string
	if scanopts.StoreResponse || scanopts.StoreChain {
		domainFile := strings.ReplaceAll(urlutil.TrimScheme(URL.String()), ":", ".")

		// On various OS the file max file name length is 255 - https://serverfault.com/questions/9546/filename-length-limits-on-linux
		// Truncating length at 255
		if len(domainFile) >= maxFileNameLength {
			// leaving last 4 bytes free to append ".txt"
			domainFile = domainFile[:maxFileNameLength]
		}

		domainFile = strings.ReplaceAll(domainFile, "/", "[slash]") + ".txt"
		// store response
		responsePath = filepath.Join(scanopts.StoreResponseDirectory, domainFile)
		respRaw := resp.Raw
		if len(respRaw) > scanopts.MaxResponseBodySizeToSave {
			respRaw = respRaw[:scanopts.MaxResponseBodySizeToSave]
		}
		writeErr := os.WriteFile(responsePath, []byte(respRaw), 0644)
		if writeErr != nil {
			gologger.Error().Msgf("Could not write response at path '%s', to disk: %s", responsePath, writeErr)
		}
		if scanopts.StoreChain && resp.HasChain() {
			domainFile = strings.ReplaceAll(domainFile, ".txt", ".chain.txt")
			responsePath = filepath.Join(scanopts.StoreResponseDirectory, domainFile)
			writeErr := os.WriteFile(responsePath, []byte(resp.GetChain()), 0644)
			if writeErr != nil {
				gologger.Warning().Msgf("Could not write response at path '%s', to disk: %s", responsePath, writeErr)
			}
		}
	}

	parsed, err := urlutil.Parse(fullURL)
	if err != nil {
		return Result{URL: fullURL, Input: origInput, err: errors.Wrap(err, "could not parse url")}
	}

	finalPort := parsed.Port
	if finalPort == "" {
		if parsed.Scheme == "http" {
			finalPort = "80"
		} else {
			finalPort = "443"
		}
	}
	finalPath := parsed.RequestURI
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

	result := Result{
		Timestamp:          time.Now(),
		Request:            request,
		ResponseHeader:     responseHeader,
		RawHeader:          rawResponseHeader,
		Scheme:             parsed.Scheme,
		Port:               finalPort,
		Path:               finalPath,
		raw:                resp.Raw,
		URL:                fullURL,
		Input:              origInput,
		ContentLength:      resp.ContentLength,
		ChainStatusCodes:   chainStatusCodes,
		Chain:              chainItems,
		StatusCode:         resp.StatusCode,
		Location:           resp.GetHeaderPart("Location", ";"),
		ContentType:        resp.GetHeaderPart("Content-Type", ";"),
		Title:              title,
		str:                builder.String(),
		VHost:              isvhost,
		WebServer:          serverHeader,
		ResponseBody:       serverResponseRaw,
		WebSocket:          isWebSocket,
		TLSData:            resp.TLSData,
		CSPData:            resp.CSPData,
		Pipeline:           pipeline,
		HTTP2:              http2,
		Method:             method,
		Host:               ip,
		A:                  ips,
		CNAMEs:             cnames,
		CDN:                isCDN,
		CDNName:            cdnName,
		ResponseTime:       resp.Duration.String(),
		Technologies:       technologies,
		FinalURL:           finalURL,
		FavIconMMH3:        faviconMMH3,
		Hashes:             hashesMap,
		Extracts:           extractResult,
		Jarm:               jarmhash,
		Lines:              resp.Lines,
		Words:              resp.Words,
		ASN:                asnResponse,
		ExtractRegex:       extractRegex,
		StoredResponsePath: responsePath,
	}
	if r.options.OnResult != nil {
		r.options.OnResult(result)
	}
	return result
}

// SaveResumeConfig to file
func (r *Runner) SaveResumeConfig() error {
	var resumeCfg ResumeCfg
	resumeCfg.Index = r.options.resumeCfg.currentIndex
	resumeCfg.ResumeFrom = r.options.resumeCfg.current
	return goconfig.Save(resumeCfg, DefaultResumeFile)
}

// JSON the result
func (r Result) JSON(scanopts *scanOptions) string { //nolint
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
	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)

	var headers []string
	ty := reflect.TypeOf(r)
	for i := 0; i < ty.NumField(); i++ {
		tag := ty.Field(i).Tag.Get("csv")

		if ignored := tag == ""; ignored {
			continue
		}

		headers = append(headers, tag)
	}
	_ = writer.Write(headers)
	writer.Flush()

	return strings.TrimSpace(buffer.String())
}

// CSVRow the CSV Row
func (r Result) CSVRow(scanopts *scanOptions) string { //nolint
	if scanopts != nil && len(r.ResponseBody) > scanopts.MaxResponseBodySizeToSave {
		r.ResponseBody = r.ResponseBody[:scanopts.MaxResponseBodySizeToSave]
	}

	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)

	var cells []string
	elem := reflect.ValueOf(r)
	for i := 0; i < elem.NumField(); i++ {
		value := elem.Field(i)
		tag := elem.Type().Field(i).Tag.Get(`csv`)
		if ignored := tag == ""; ignored {
			continue
		}

		str := fmt.Sprintf("%v", value.Interface())

		// defense against csv injection
		startWithRiskyChar, _ := regexp.Compile(`^([=+\-@])`)
		if startWithRiskyChar.Match([]byte(str)) {
			str = "'" + str
		}

		cells = append(cells, str)
	}
	_ = writer.Write(cells)
	writer.Flush()

	return strings.TrimSpace(buffer.String()) // remove "\n" in the end
}

func (r *Runner) skipCDNPort(host string, port string) bool {
	// if the option is not enabled we don't skip
	if !r.options.ExcludeCDN {
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

	isCdnIP, _, err := r.hp.CdnCheck(hostIP)
	if err != nil {
		return false
	}

	// If the target is part of the CDN ips range - only ports 80 and 443 are allowed
	if isCdnIP && port != "80" && port != "443" {
		return true
	}

	return false
}

func getDNSData(hp *httpx.HTTPX, hostname string) (ips, cnames []string, err error) {
	dnsData, err := hp.Dialer.GetDNSData(hostname)
	if err != nil {
		return nil, nil, err
	}
	ips = make([]string, 0, len(dnsData.A)+len(dnsData.AAAA))
	ips = append(ips, dnsData.A...)
	ips = append(ips, dnsData.AAAA...)
	cnames = dnsData.CNAME
	return
}

func normalizeHeaders(headers map[string][]string) map[string]interface{} {
	normalized := make(map[string]interface{}, len(headers))
	for k, v := range headers {
		normalized[strings.ReplaceAll(strings.ToLower(k), "-", "_")] = strings.Join(v, ", ")
	}
	return normalized
}
