package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
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
	scanopts.ResponseTime = options.ResponseTime
	scanopts.Method = options.Method
	scanopts.Timeout = httpxOptions.Timeout
	scanopts.Smuggling = options.Smuggling
	scanopts.OutputServerHeader = options.OutputServerHeader

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
	Smuggling              bool
	OutputTitle            bool
	OutputStatusCode       bool
	OutputContentLength    bool
	StoreResponse          bool
	ResponseTime           bool
	StoreResponseDirectory string
	Timeout                time.Duration
	OutputServerHeader     bool
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
		builder.WriteString(fmt.Sprintf(" [%d]", resp.StatusCode))
	}

	if scanopts.OutputContentLength {
		builder.WriteString(fmt.Sprintf(" [%d]", resp.ContentLength))
	}

	if scanopts.ResponseTime {
		builder.WriteString(fmt.Sprintf(" [%s]", resp.Duration.String()))
	}

	title := httpx.ExtractTitle(resp)
	if scanopts.OutputTitle {
		builder.WriteString(fmt.Sprintf(" [%s]", title))
	}

	serverHeader := resp.GetHeader("Server")
	if scanopts.OutputServerHeader {
		builder.WriteString(fmt.Sprintf(" [%s]", serverHeader))
	}

	// check for virtual host
	isvhost := false
	if scanopts.VHost {
		isvhost, _ = hp.IsVirtualHost(req)
		if isvhost {
			builder.WriteString(" [vhost]")
		}
	}

	// check for smuggling
	issmuggable := false
	if scanopts.Smuggling {
		smugglingPort := 80
		if protocol == "https" {
			smugglingPort = 443
		}
		issmuggable, err = hp.IsSmugglable(protocol, domain, smugglingPort, scanopts.Method, resp.Duration, scanopts.Timeout)
		if issmuggable {
			builder.WriteString(" [smuggable]")
		}
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

	output <- Result{URL: fullURL, ContentLength: resp.ContentLength, StatusCode: resp.StatusCode, Title: title, str: builder.String(), VHost: isvhost, WebServer: serverHeader}
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
}

// JSON the result
func (r *Result) JSON() string {
	if js, err := json.Marshal(r); err == nil {
		return string(js)
	}

	return ""
}
