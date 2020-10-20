package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/cache"
	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/httputilz"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/iputil"
	"github.com/projectdiscovery/httpx/common/slice"
	"github.com/projectdiscovery/httpx/common/stringz"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/rawhttp"
	"github.com/remeh/sizedwaitgroup"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	options  *Options
	hp       *httpx.HTTPX
	scanopts *scanOptions
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	httpxOptions := httpx.DefaultOptions
	httpxOptions.Timeout = time.Duration(options.Timeout) * time.Second
	httpxOptions.RetryMax = options.Retries
	httpxOptions.FollowRedirects = options.FollowRedirects
	httpxOptions.FollowHostRedirects = options.FollowHostRedirects
	httpxOptions.HTTPProxy = options.HTTPProxy
	httpxOptions.Unsafe = options.Unsafe
	httpxOptions.RequestOverride = httpx.RequestOverride{URIPath: options.RequestURI}
	httpxOptions.CdnCheck = options.OutputCDN

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

	var err error
	runner.hp, err = httpx.New(&httpxOptions)
	if err != nil {
		gologger.Fatalf("Could not create httpx instance: %s\n", err)
	}

	var scanopts scanOptions

	if options.InputRawRequest != "" {
		var rawRequest []byte
		rawRequest, err = ioutil.ReadFile(options.InputRawRequest)
		if err != nil {
			gologger.Fatalf("Could not read raw request from '%s': %s\n", options.InputRawRequest, err)
		}

		rrMethod, rrPath, rrHeaders, rrBody, err := httputilz.ParseRequest(string(rawRequest), options.Unsafe)
		if err != nil {
			gologger.Fatalf("Could not parse raw request: %s\n", err)
		}
		scanopts.Methods = append(scanopts.Methods, rrMethod)
		scanopts.RequestURI = rrPath
		for name, value := range rrHeaders {
			httpxOptions.CustomHeaders[name] = value
		}
		scanopts.RequestBody = rrBody
		options.rawRequest = string(rawRequest)
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
		scanopts.Methods = httputilz.AllHTTPMethods()
	} else if options.Methods != "" {
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
	scanopts.OutputWebSocket = options.OutputWebSocket
	scanopts.TLSProbe = options.TLSProbe
	scanopts.CSPProbe = options.CSPProbe
	if options.RequestURI != "" {
		scanopts.RequestURI = options.RequestURI
	}
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

	// output verb if more than one is specified
	if len(scanopts.Methods) > 1 && !options.Silent {
		scanopts.OutputMethod = true
	}

	runner.scanopts = &scanopts

	return runner, nil
}

func (runner *Runner) Close() {
	// not implemented
}

func (runner *Runner) RunEnumeration() {
	// Try to create output folder if it doesnt exist
	if runner.options.StoreResponse && !fileutil.FolderExists(runner.options.StoreResponseDir) {
		if err := os.MkdirAll(runner.options.StoreResponseDir, os.ModePerm); err != nil {
			gologger.Fatalf("Could not create output directory '%s': %s\n", runner.options.StoreResponseDir, err)
		}
	}

	// output routine
	wgoutput := sizedwaitgroup.New(1)
	wgoutput.Add()
	output := make(chan Result)
	go func(output chan Result) {
		defer wgoutput.Done()

		var f *os.File
		if runner.options.Output != "" {
			var err error
			f, err = os.Create(runner.options.Output)
			if err != nil {
				gologger.Fatalf("Could not create output file '%s': %s\n", runner.options.Output, err)
			}
			//nolint:errcheck // this method needs a small refactor to reduce complexity
			defer f.Close()
		}
		for r := range output {
			if r.err != nil {
				gologger.Debugf("Failure '%s': %s\n", r.URL, r.err)
				continue
			}

			// apply matchers and filters
			if len(runner.options.filterStatusCode) > 0 && slice.IntSliceContains(runner.options.filterStatusCode, r.StatusCode) {
				continue
			}
			if len(runner.options.filterContentLength) > 0 && slice.IntSliceContains(runner.options.filterContentLength, r.ContentLength) {
				continue
			}
			if runner.options.filterRegex != nil && runner.options.filterRegex.MatchString(r.raw) {
				continue
			}
			if runner.options.OutputFilterString != "" && strings.Contains(strings.ToLower(r.raw), strings.ToLower(runner.options.OutputFilterString)) {
				continue
			}
			if len(runner.options.matchStatusCode) > 0 && !slice.IntSliceContains(runner.options.matchStatusCode, r.StatusCode) {
				continue
			}
			if len(runner.options.matchContentLength) > 0 && !slice.IntSliceContains(runner.options.matchContentLength, r.ContentLength) {
				continue
			}
			if runner.options.matchRegex != nil && !runner.options.matchRegex.MatchString(r.raw) {
				continue
			}
			if runner.options.OutputMatchString != "" && !strings.Contains(strings.ToLower(r.raw), strings.ToLower(runner.options.OutputMatchString)) {
				continue
			}

			row := r.str
			if runner.options.JSONOutput {
				row = r.JSON()
			}

			gologger.Silentf("%s\n", row)
			if f != nil {
				//nolint:errcheck // this method needs a small refactor to reduce complexity
				f.WriteString(row + "\n")
			}
		}
	}(output)

	wg := sizedwaitgroup.New(runner.options.Threads)
	var scanner *bufio.Scanner

	// check if file has been provided
	if fileutil.FileExists(runner.options.InputFile) {
		finput, err := os.Open(runner.options.InputFile)
		if err != nil {
			gologger.Fatalf("Could read input file '%s': %s\n", runner.options.InputFile, err)
		}
		scanner = bufio.NewScanner(finput)
		defer func() {
			err := finput.Close()
			if err != nil {
				gologger.Fatalf("Could close input file '%s': %s\n", runner.options.InputFile, err)
			}
		}()
	} else if fileutil.HasStdin() {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		gologger.Fatalf("No input provided")
	}

	for scanner.Scan() {
		process(scanner.Text(), &wg, runner.hp, runner.options.protocol, runner.scanopts, output)
	}

	if err := scanner.Err(); err != nil {
		gologger.Fatalf("Read error on standard input: %s", err)
	}

	wg.Wait()

	close(output)

	wgoutput.Wait()
}

func process(t string, wg *sizedwaitgroup.SizedWaitGroup, hp *httpx.HTTPX, protocol string, scanopts *scanOptions, output chan Result) {
	protocols := []string{protocol}
	if scanopts.NoFallback {
		protocols = []string{httpx.HTTPS, httpx.HTTP}
	}
	for target := range targets(stringz.TrimProtocol(t)) {
		// if no custom ports specified then test the default ones
		if len(customport.Ports) == 0 {
			for _, method := range scanopts.Methods {
				for _, prot := range protocols {
					wg.Add()
					go func(target, method, protocol string) {
						defer wg.Done()
						r := analyze(hp, protocol, target, 0, method, scanopts)
						output <- r
						if scanopts.TLSProbe && r.TLSData != nil {
							scanopts.TLSProbe = false
							for _, tt := range r.TLSData.DNSNames {
								process(tt, wg, hp, protocol, scanopts, output)
							}
							for _, tt := range r.TLSData.CommonName {
								process(tt, wg, hp, protocol, scanopts, output)
							}
						}
						if scanopts.CSPProbe && r.CSPData != nil {
							scanopts.CSPProbe = false
							for _, tt := range r.CSPData.Domains {
								process(tt, wg, hp, protocol, scanopts, output)
							}
						}
					}(target, method, prot)
				}
			}
		}

		// the host name shouldn't have any semicolon - in case remove the port
		semicolonPosition := strings.LastIndex(target, ":")
		if semicolonPosition > 0 {
			target = target[:semicolonPosition]
		}

		for port, wantedProtocol := range customport.Ports {
			for _, method := range scanopts.Methods {
				wg.Add()
				go func(port int, method, protocol string) {
					defer wg.Done()
					r := analyze(hp, protocol, target, port, method, scanopts)
					output <- r
					if scanopts.TLSProbe && r.TLSData != nil {
						scanopts.TLSProbe = false
						for _, tt := range r.TLSData.DNSNames {
							process(tt, wg, hp, protocol, scanopts, output)
						}
						for _, tt := range r.TLSData.CommonName {
							process(tt, wg, hp, protocol, scanopts, output)
						}
					}
				}(port, method, wantedProtocol)
			}
		}
	}
}

// returns all the targets within a cidr range or the single target
func targets(target string) chan string {
	results := make(chan string)
	go func() {
		defer close(results)

		// A valid target does not contain:
		// *
		// spaces
		if strings.ContainsAny(target, " *") {
			return
		}

		// test if the target is a cidr
		if iputil.IsCidr(target) {
			cidrIps, err := mapcidr.IPAddresses(target)
			if err != nil {
				return
			}
			for _, ip := range cidrIps {
				results <- ip
			}
		} else {
			results <- target
		}
	}()
	return results
}

func analyze(hp *httpx.HTTPX, protocol, domain string, port int, method string, scanopts *scanOptions) Result {
	origProtocol := protocol
	if protocol == httpx.HTTPorHTTPS {
		protocol = httpx.HTTPS
	}
	retried := false
retry:
	URL := fmt.Sprintf("%s://%s", protocol, domain)
	if port > 0 {
		URL = fmt.Sprintf("%s://%s:%d", protocol, domain, port)
	}

	if !scanopts.Unsafe {
		URL += scanopts.RequestURI
	}

	req, err := hp.NewRequest(method, URL)
	if err != nil {
		return Result{URL: URL, err: err}
	}

	hp.SetCustomHeaders(req, hp.CustomHeaders)
	if scanopts.RequestBody != "" {
		req.ContentLength = int64(len(scanopts.RequestBody))
		req.Body = ioutil.NopCloser(strings.NewReader(scanopts.RequestBody))
	}

	resp, err := hp.Do(req)
	if err != nil {
		if !retried && origProtocol == httpx.HTTPorHTTPS {
			if protocol == httpx.HTTPS {
				protocol = httpx.HTTP
			} else {
				protocol = httpx.HTTPS
			}
			retried = true
			goto retry
		}
		return Result{URL: URL, err: err}
	}

	var fullURL string

	if resp.StatusCode >= 0 {
		if port > 0 {
			fullURL = fmt.Sprintf("%s://%s:%d%s", protocol, domain, port, scanopts.RequestURI)
		} else {
			fullURL = fmt.Sprintf("%s://%s%s", protocol, domain, scanopts.RequestURI)
		}
	}

	builder := &strings.Builder{}

	builder.WriteString(fullURL)

	if scanopts.OutputStatusCode {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			// Color the status code based on its value
			switch {
			case resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices:
				builder.WriteString(aurora.Green(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest:
				builder.WriteString(aurora.Yellow(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError:
				builder.WriteString(aurora.Red(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode > http.StatusInternalServerError:
				builder.WriteString(aurora.Bold(aurora.Yellow(strconv.Itoa(resp.StatusCode))).String())
			}
		} else {
			builder.WriteString(strconv.Itoa(resp.StatusCode))
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

	var serverResponseRaw = ""
	if scanopts.ResponseInStdout {
		serverResponseRaw = resp.Raw
	}

	// check for virtual host
	isvhost := false
	if scanopts.VHost {
		isvhost, _ = hp.IsVirtualHost(req)
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
		pipeline = hp.SupportPipeline(protocol, method, domain, port)
		if pipeline {
			builder.WriteString(" [pipeline]")
		}
	}

	var http2 bool
	// if requested probes for http2
	if scanopts.HTTP2Probe {
		http2 = hp.SupportHTTP2(protocol, method, URL)
		if http2 {
			builder.WriteString(" [http2]")
		}
	}

	ip := cache.GetDialedIP(domain)
	if scanopts.OutputIP {
		builder.WriteString(fmt.Sprintf(" [%s]", ip))
	}

	var (
		ips    []string
		cnames []string
	)
	dnsData, err := cache.GetDNSData(domain)
	if dnsData != nil && err == nil {
		ips = append(ips, dnsData.IP4s...)
		ips = append(ips, dnsData.IP6s...)
		cnames = dnsData.CNAMEs
	} else {
		ips = append(ips, ip)
	}

	if scanopts.OutputCName && len(cnames) > 0 {
		// Print only the first CNAME (full list in json)
		builder.WriteString(fmt.Sprintf(" [%s]", cnames[0]))
	}

	isCDN, err := hp.CdnCheck(ip)
	if scanopts.OutputCDN && isCDN && err == nil {
		builder.WriteString(" [cdn]")
	}

	if scanopts.OutputResponseTime {
		builder.WriteString(fmt.Sprintf(" [%s]", resp.Duration))
	}

	// store responses in directory
	if scanopts.StoreResponse {
		domainFile := fmt.Sprintf("%s%s", domain, scanopts.RequestURI)
		if port > 0 {
			domainFile = fmt.Sprintf("%s.%d%s", domain, port, scanopts.RequestURI)
		}
		// On various OS the file max file name length is 255 - https://serverfault.com/questions/9546/filename-length-limits-on-linux
		// Truncating length at 255
		if len(domainFile) >= maxFileNameLenght {
			// leaving last 4 bytes free to append ".txt"
			domainFile = domainFile[:maxFileNameLenght-1]
		}

		domainFile = strings.ReplaceAll(domainFile, "/", "_") + ".txt"
		responsePath := path.Join(scanopts.StoreResponseDirectory, domainFile)
		err := ioutil.WriteFile(responsePath, []byte(resp.Raw), 0644)
		if err != nil {
			gologger.Warningf("Could not write response, at path '%s', to disc.", responsePath)
		}
	}

	return Result{
		raw:           resp.Raw,
		URL:           fullURL,
		ContentLength: resp.ContentLength,
		StatusCode:    resp.StatusCode,
		Location:      resp.GetHeaderPart("Location", ";"),
		ContentType:   resp.GetHeaderPart("Content-Type", ";"),
		Title:         title,
		str:           builder.String(),
		VHost:         isvhost,
		WebServer:     serverHeader,
		Response:      serverResponseRaw,
		WebSocket:     isWebSocket,
		TLSData:       resp.TLSData,
		CSPData:       resp.CSPData,
		Pipeline:      pipeline,
		HTTP2:         http2,
		Method:        method,
		IP:            ip,
		IPs:           ips,
		CNAMEs:        cnames,
		CDN:           isCDN,
		ResponseTime:  resp.Duration.String(),
	}
}

// Result of a scan
type Result struct {
	IPs           []string `json:"ips"`
	CNAMEs        []string `json:"cnames,omitempty"`
	raw           string
	URL           string `json:"url"`
	Location      string `json:"location"`
	Title         string `json:"title"`
	str           string
	err           error
	WebServer     string         `json:"webserver"`
	Response      string         `json:"serverResponse,omitempty"`
	ContentType   string         `json:"content-type,omitempty"`
	Method        string         `json:"method"`
	IP            string         `json:"ip"`
	ContentLength int            `json:"content-length"`
	StatusCode    int            `json:"status-code"`
	TLSData       *httpx.TLSData `json:"tls,omitempty"`
	CSPData       *httpx.CSPData `json:"csp,omitempty"`
	VHost         bool           `json:"vhost"`
	WebSocket     bool           `json:"websocket,omitempty"`
	Pipeline      bool           `json:"pipeline,omitempty"`
	HTTP2         bool           `json:"http2"`
	CDN           bool           `json:"cdn,omitempty"`
	ResponseTime  string         `json:"response-time"`
}

// JSON the result
func (r *Result) JSON() string {
	if js, err := json.Marshal(r); err == nil {
		return string(js)
	}

	return ""
}
