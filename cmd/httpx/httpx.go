package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/customheader"
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

func main() {
	options := ParseOptions()

	httpxOptions := httpx.DefaultOptions
	httpxOptions.Timeout = time.Duration(options.Timeout) * time.Second
	httpxOptions.RetryMax = options.Retries
	httpxOptions.FollowRedirects = options.FollowRedirects
	httpxOptions.FollowHostRedirects = options.FollowHostRedirects
	httpxOptions.HttpProxy = options.HttpProxy
	httpxOptions.Unsafe = options.Unsafe
	httpxOptions.RequestOverride = httpx.RequestOverride{URIPath: options.RequestURI}

	var key, value string
	httpxOptions.CustomHeaders = make(map[string]string)
	for _, customHeader := range options.CustomHeaders {
		tokens := strings.SplitN(customHeader, ":", 2)
		// if it's an invalid header skip it
		if len(tokens) < 2 {
			continue
		}
		key = strings.TrimSpace(tokens[0])
		value = strings.TrimSpace(tokens[1])

		httpxOptions.CustomHeaders[key] = value
	}

	hp, err := httpx.New(&httpxOptions)
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

		rrMethod, rrPath, rrHeaders, rrBody, err := httputilz.ParseRequest(string(rawRequest))
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
	if options.Unsafe {
		_, ok := httpxOptions.CustomHeaders["Host"]
		if ok {
			rawhttp.AutomaticHostHeader(false)
		}
	}

	if options.Methods != "" {
		scanopts.Methods = append(scanopts.Methods, strings.Split(options.Methods, ",")...)
	}
	if len(scanopts.Methods) == 0 {
		scanopts.Methods = append(scanopts.Methods, "GET")
	}
	protocol := "https"
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
	scanopts.TlsProbe = options.TLSProbe
	scanopts.CspProbe = options.CSPProbe
	if options.RequestURI != "" {
		scanopts.RequestURI = options.RequestURI
	}
	scanopts.OutputContentType = options.OutputContentType
	scanopts.RequestBody = options.RequestBody
	scanopts.Unsafe = options.Unsafe
	scanopts.Pipeline = options.Pipeline
	scanopts.HTTP2Probe = options.HTTP2Probe
	scanopts.OutputMethod = options.OutputMethod
	if len(scanopts.Methods) > 0 {
		scanopts.OutputMethod = true

		// Try to create output folder if it doesnt exist
		if options.StoreResponse && !fileutil.FolderExists(options.StoreResponseDir) {
			if err := os.MkdirAll(options.StoreResponseDir, os.ModePerm); err != nil {
				gologger.Fatalf("Could not create output directory '%s': %s\n", options.StoreResponseDir, err)
			}
		}

		// output routine
		wgoutput := sizedwaitgroup.New(1)
		wgoutput.Add()
		output := make(chan Result)
		go func(output chan Result) {
			defer wgoutput.Done()

			var f *os.File
			if options.Output != "" {
				var err error
				f, err = os.Create(options.Output)
				if err != nil {
					gologger.Fatalf("Could not create output file '%s': %s\n", options.Output, err)
				}
				defer f.Close()
			}
			for r := range output {
				if r.err != nil {
					gologger.Debugf("Failure '%s': %s\n", r.URL, r.err)
					continue
				}

				// apply matchers and filters
				if len(options.filterStatusCode) > 0 && slice.IntSliceContains(options.filterStatusCode, r.StatusCode) {
					continue
				}
				if len(options.filterContentLength) > 0 && slice.IntSliceContains(options.filterContentLength, r.ContentLength) {
					continue
				}
				if len(options.matchStatusCode) > 0 && !slice.IntSliceContains(options.matchStatusCode, r.StatusCode) {
					continue
				}
				if len(options.matchContentLength) > 0 && !slice.IntSliceContains(options.matchContentLength, r.ContentLength) {
					continue
				}

				row := r.str
				if options.JSONOutput {
					row = r.JSON()
				}

				gologger.Silentf("%s\n", row)
				if f != nil {
					f.WriteString(row + "\n")
				}
			}
		}(output)

		wg := sizedwaitgroup.New(options.Threads)
		var sc *bufio.Scanner

		// check if file has been provided
		if fileutil.FileExists(options.InputFile) {
			finput, err := os.Open(options.InputFile)
			if err != nil {
				gologger.Fatalf("Could read input file '%s': %s\n", options.InputFile, err)
			}
			defer finput.Close()
			sc = bufio.NewScanner(finput)
		} else if fileutil.HasStdin() {
			sc = bufio.NewScanner(os.Stdin)
		} else {
			gologger.Fatalf("No input provided")
		}

		for sc.Scan() {
			process(sc.Text(), &wg, hp, protocol, scanopts, output)
		}

		wg.Wait()

		close(output)

		wgoutput.Wait()
	}
}

func process(t string, wg *sizedwaitgroup.SizedWaitGroup, hp *httpx.HTTPX, protocol string, scanopts scanOptions, output chan Result) {
	for target := range targets(stringz.TrimProtocol(t)) {
		// if no custom ports specified then test the default ones
		if len(customport.Ports) == 0 {
			for _, method := range scanopts.Methods {
				wg.Add()
				go func(target, method string) {
					defer wg.Done()
					r := analyze(hp, protocol, target, 0, method, &scanopts)
					output <- r
					if scanopts.TlsProbe && r.TlsData != nil {
						scanopts.TlsProbe = false
						for _, tt := range r.TlsData.DNSNames {
							process(tt, wg, hp, protocol, scanopts, output)
						}
						for _, tt := range r.TlsData.CommonName {
							process(tt, wg, hp, protocol, scanopts, output)
						}
					}
					if scanopts.CspProbe && r.CspData != nil {
						scanopts.CspProbe = false
						for _, tt := range r.CspData.Domains {
							process(tt, wg, hp, protocol, scanopts, output)
						}
					}
				}(target, method)
			}
		}

		// the host name shouldn't have any semicolon - in case remove the port
		semicolonPosition := strings.LastIndex(target, ":")
		if semicolonPosition > 0 {
			target = target[:semicolonPosition]
		}

		for port := range customport.Ports {
			for _, method := range scanopts.Methods {
				wg.Add()
				go func(port int, method string) {
					defer wg.Done()
					r := analyze(hp, protocol, target, port, method, &scanopts)
					output <- r
					if scanopts.TlsProbe && r.TlsData != nil {
						scanopts.TlsProbe = false
						for _, tt := range r.TlsData.DNSNames {
							process(tt, wg, hp, protocol, scanopts, output)
						}
						for _, tt := range r.TlsData.CommonName {
							process(tt, wg, hp, protocol, scanopts, output)
						}
					}
				}(port, method)
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

type scanOptions struct {
	Methods                []string
	VHost                  bool
	OutputTitle            bool
	OutputStatusCode       bool
	OutputLocation         bool
	OutputContentLength    bool
	StoreResponse          bool
	StoreResponseDirectory string
	OutputServerHeader     bool
	OutputWebSocket        bool
	OutputWithNoColor      bool
	OutputMethod           bool
	ResponseInStdout       bool
	TlsProbe               bool
	CspProbe               bool
	RequestURI             string
	OutputContentType      bool
	RequestBody            string
	Unsafe                 bool
	Pipeline               bool
	HTTP2Probe             bool
}

func analyze(hp *httpx.HTTPX, protocol string, domain string, port int, method string, scanopts *scanOptions) Result {
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
		req.Body = ioutil.NopCloser(strings.NewReader(scanopts.RequestBody))
	}

	resp, err := hp.Do(req)
	if err != nil {
		if !retried {
			if protocol == "https" {
				protocol = "http"
			} else {
				protocol = "https"
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
			case resp.StatusCode >= 200 && resp.StatusCode < 300:
				builder.WriteString(aurora.Green(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode >= 300 && resp.StatusCode < 400:
				builder.WriteString(aurora.Yellow(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode >= 400 && resp.StatusCode < 500:
				builder.WriteString(aurora.Red(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode > 500:
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

	// store responses in directory
	if scanopts.StoreResponse {
		domainFile := fmt.Sprintf("%s%s", domain, scanopts.RequestURI)
		if port > 0 {
			domainFile = fmt.Sprintf("%s.%d%s", domain, port, scanopts.RequestURI)
		}
		domainFile = strings.Replace(domainFile, "/", "_", -1) + ".txt"
		responsePath := path.Join(scanopts.StoreResponseDirectory, domainFile)
		err := ioutil.WriteFile(responsePath, []byte(resp.Raw), 0644)
		if err != nil {
			gologger.Fatalf("Could not write response, at path '%s', to disc.", responsePath)
		}
	}

	return Result{
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
		TlsData:       resp.TlsData,
		CspData:       resp.CspData,
		Pipeline:      pipeline,
		HTTP2:         http2,
		Method:        method,
	}

}

// Result of a scan
type Result struct {
	URL           string `json:"url"`
	ContentLength int    `json:"content-length"`
	StatusCode    int    `json:"status-code"`
	Location      string `json:"location"`
	Title         string `json:"title"`
	str           string
	err           error
	VHost         bool           `json:"vhost"`
	WebServer     string         `json:"webserver"`
	Response      string         `json:"serverResponse,omitempty"`
	WebSocket     bool           `json:"websocket,omitempty"`
	ContentType   string         `json:"content-type,omitempty"`
	TlsData       *httpx.TlsData `json:"tls,omitempty"`
	CspData       *httpx.CspData `json:"csp,omitempty"`
	Pipeline      bool           `json:"pipeline,omitempty"`
	HTTP2         bool           `json:"http2"`
	Method        string         `json:"method"`
}

// JSON the result
func (r *Result) JSON() string {
	if js, err := json.Marshal(r); err == nil {
		return string(js)
	}

	return ""
}

// Options contains configuration options for chaos client.
type Options struct {
	VHost                     bool
	Smuggling                 bool
	ExtractTitle              bool
	StatusCode                bool
	Location                  bool
	ContentLength             bool
	Retries                   int
	Threads                   int
	Timeout                   int
	CustomHeaders             customheader.CustomHeaders
	CustomPorts               customport.CustomPorts
	Output                    string
	FollowRedirects           bool
	StoreResponse             bool
	StoreResponseDir          string
	HttpProxy                 string
	SocksProxy                string
	JSONOutput                bool
	InputFile                 string
	Methods                   string
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
	RequestURI                string
	OutputContentType         bool
	OutputMatchStatusCode     string
	matchStatusCode           []int
	OutputMatchContentLength  string
	matchContentLength        []int
	OutputFilterStatusCode    string
	filterStatusCode          []int
	OutputFilterContentLength string
	filterContentLength       []int
	InputRawRequest           string
	rawRequest                string
	Unsafe                    bool
	RequestBody               string
	Debug                     bool
	Pipeline                  bool
	HTTP2Probe                bool
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
	flag.StringVar(&options.HttpProxy, "http-proxy", "", "HTTP Proxy, eg http://127.0.0.1:8080")
	flag.BoolVar(&options.JSONOutput, "json", false, "JSON Output")
	flag.StringVar(&options.InputFile, "l", "", "File containing domains")
	flag.StringVar(&options.Methods, "x", "", "Request Methods")
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

const banner = `
    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|  
             /_/              v1.0
`

// Version is the current version of httpx
const Version = `1.0.0`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Printf("%s\n", banner)
	gologger.Printf("\t\tprojectdiscovery.io\n\n")

	gologger.Labelf("Use with caution. You are responsible for your actions\n")
	gologger.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
