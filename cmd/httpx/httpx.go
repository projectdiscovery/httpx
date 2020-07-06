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
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/iputil"
	"github.com/projectdiscovery/httpx/common/stringz"
	"github.com/remeh/sizedwaitgroup"
)

func main() {
	options := ParseOptions()
	options.validateOptions()

	httpxOptions := httpx.DefaultOptions
	httpxOptions.Timeout = time.Duration(options.Timeout) * time.Second
	httpxOptions.RetryMax = options.Retries
	httpxOptions.FollowRedirects = options.FollowRedirects
	httpxOptions.FollowHostRedirects = options.FollowHostRedirects
	httpxOptions.HttpProxy = options.HttpProxy

	httpxOptions.CustomHeaders = make(map[string]string)
	for _, customHeader := range options.CustomHeaders {
		tokens := strings.Split(customHeader, ":")
		// if it's an invalid header skip it
		if len(tokens) < 2 {
			continue
		}

		httpxOptions.CustomHeaders[tokens[0]] = tokens[1]
	}

	hp, err := httpx.New(&httpxOptions)
	if err != nil {
		gologger.Fatalf("Could not create httpx instance: %s\n", err)
	}

	var scanopts scanOptions
	scanopts.Method = options.Method
	protocol := "https"
	scanopts.VHost = options.VHost
	scanopts.OutputTitle = options.ExtractTitle
	scanopts.OutputStatusCode = options.StatusCode
	scanopts.OutputContentLength = options.ContentLength
	scanopts.StoreResponse = options.StoreResponse
	scanopts.StoreResponseDirectory = options.StoreResponseDir
	scanopts.Method = options.Method
	scanopts.OutputServerHeader = options.OutputServerHeader
	scanopts.OutputWithNoColor = options.NoColor
	scanopts.ResponseInStdout = options.responseInStdout
	scanopts.OutputWebSocket = options.OutputWebSocket

	// Try to create output folder if it doesnt exist
	if options.StoreResponse && options.StoreResponseDir != "" && options.StoreResponseDir != "." {
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
				continue
			}
			row := r.str
			if options.JSONOutput {
				row = r.JSON()
			}

			fmt.Println(row)
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
		for target := range targets(stringz.TrimProtocol(sc.Text())) {
			// if no custom ports specified then test the default ones
			if len(customport.Ports) == 0 {
				wg.Add()
				go func(target string) {
					defer wg.Done()
					analyze(hp, protocol, target, 0, &scanopts, output)
				}(target)
			}

			// the host name shouldn't have any semicolon - in case remove the port
			semicolonPosition := strings.LastIndex(target, ":")
			if semicolonPosition > 0 {
				target = target[:semicolonPosition]
			}

			for port := range customport.Ports {
				wg.Add()
				go func(port int) {
					defer wg.Done()
					analyze(hp, protocol, target, port, &scanopts, output)
				}(port)
			}
		}
	}

	wg.Wait()

	close(output)

	wgoutput.Wait()
}

// returns all the targets within a cidr range or the single target
func targets(target string) chan string {
	results := make(chan string)
	go func() {
		defer close(results)

		// test if the target is a cidr
		if iputil.IsCidr(target) {
			cidrIps, err := iputil.Ips(target)
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
	Method                 string
	VHost                  bool
	OutputTitle            bool
	OutputStatusCode       bool
	OutputContentLength    bool
	StoreResponse          bool
	StoreResponseDirectory string
	OutputServerHeader     bool
	OutputWebSocket        bool
	OutputWithNoColor      bool
	ResponseInStdout       bool
}

func analyze(hp *httpx.HTTPX, protocol string, domain string, port int, scanopts *scanOptions, output chan Result) {
	retried := false
retry:
	URL := fmt.Sprintf("%s://%s", protocol, domain)
	if port > 0 {
		URL = fmt.Sprintf("%s:%d", URL, port)
	}

	req, err := hp.NewRequest(scanopts.Method, URL)
	if err != nil {
		output <- Result{URL: URL, err: err}
		return
	}

	hp.SetCustomHeaders(req, hp.CustomHeaders)

	resp, err := hp.Do(req)
	if err != nil {
		output <- Result{URL: URL, err: err}
		if !retried {
			if protocol == "https" {
				protocol = "http"
			} else {
				protocol = "https"
			}
			retried = true
			goto retry
		}
		return
	}

	var fullURL string

	if resp.StatusCode >= 0 {
		if port > 0 {
			fullURL = fmt.Sprintf("%s://%s:%d", protocol, domain, port)
		} else {
			fullURL = fmt.Sprintf("%s://%s", protocol, domain)
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

	if scanopts.OutputContentLength {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(strconv.Itoa(resp.ContentLength)).String())
		} else {
			builder.WriteString(strconv.Itoa(resp.ContentLength))
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

	// store responses in directory
	if scanopts.StoreResponse {
		var domainFile = strings.Replace(domain, "/", "_", -1) + ".txt"
		responsePath := path.Join(scanopts.StoreResponseDirectory, domainFile)
		err := ioutil.WriteFile(responsePath, []byte(resp.Raw), 0644)
		if err != nil {
			gologger.Fatalf("Could not write response, at path '%s', to disc.", responsePath)
		}
	}

	output <- Result{URL: fullURL, ContentLength: resp.ContentLength, StatusCode: resp.StatusCode, Title: title, str: builder.String(), VHost: isvhost, WebServer: serverHeader, Response: serverResponseRaw, WebSocket: isWebSocket}
}

// Result of a scan
type Result struct {
	URL           string `json:"url"`
	ContentLength int    `json:"content-length"`
	StatusCode    int    `json:"status-code"`
	Title         string `json:"title"`
	str           string
	err           error
	VHost         bool   `json:"vhost"`
	WebServer     string `json:"webserver"`
	Response      string `json:"serverResponse,omitempty"`
	WebSocket     bool   `json:"websocket,omitempty"`
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
	RawRequestFile      string
	VHost               bool
	Smuggling           bool
	ExtractTitle        bool
	StatusCode          bool
	ContentLength       bool
	Retries             int
	Threads             int
	Timeout             int
	CustomHeaders       customheader.CustomHeaders
	CustomPorts         customport.CustomPorts
	Output              string
	FollowRedirects     bool
	StoreResponse       bool
	StoreResponseDir    string
	HttpProxy           string
	SocksProxy          string
	JSONOutput          bool
	InputFile           string
	Method              string
	Silent              bool
	Version             bool
	Verbose             bool
	NoColor             bool
	OutputServerHeader  bool
	OutputWebSocket     bool
	responseInStdout    bool
	FollowHostRedirects bool
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
	flag.BoolVar(&options.FollowHostRedirects, "follow-host-redirects", false, "Only follow redirects on the same host")
	flag.StringVar(&options.HttpProxy, "http-proxy", "", "Http Proxy, eg http://127.0.0.1:8080")
	flag.BoolVar(&options.JSONOutput, "json", false, "JSON Output")
	flag.StringVar(&options.InputFile, "l", "", "File containing domains")
	flag.StringVar(&options.Method, "x", "GET", "Request Method")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&options.Version, "version", false, "Show version of httpx")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose Mode")
	flag.BoolVar(&options.NoColor, "no-color", false, "No Color")
	flag.BoolVar(&options.OutputServerHeader, "web-server", false, "Prints out the Server header content")
	flag.BoolVar(&options.OutputWebSocket, "websocket", false, "Prints out if the server exposes a websocket")
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

const banner = `
    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|  
             /_/              v1           
`

// Version is the current version of httpx
const Version = `0.0.5`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Printf("%s\n", banner)
	gologger.Printf("\t\tprojectdiscovery.io\n\n")

	gologger.Labelf("Use with caution. You are responsible for your actions\n")
	gologger.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
