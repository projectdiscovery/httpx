package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/httpx/internal/testutils"
)

func init() {
	// Add vhost test cases to the http test suite
	httpTestcases["VHost Input Basic"] = &vhostBasic{}
	httpTestcases["VHost Input with Proxy"] = &vhostWithProxy{}
	httpTestcases["VHost Input Invalid Format"] = &vhostInvalidFormat{}
	httpTestcases["VHost Input Multiple Targets"] = &vhostMultipleTargets{}
}

// Test basic vhost-input functionality
type vhostBasic struct{}

func (v *vhostBasic) Execute() error {
	// Create a test server
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Return the Host header so we can verify it's set correctly
		w.Header().Set("X-Host-Header", r.Host)
		fmt.Fprintf(w, "Host: %s", r.Host)
	}))
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Extract IP from the test server URL
	tsURL, _ := url.Parse(ts.URL)
	serverIP := strings.Split(tsURL.Host, ":")[0]
	serverPort := tsURL.Port()

	// Test vhost-input with the test server's IP
	input := fmt.Sprintf("test.example.com[%s]", serverIP)
	if serverPort != "" && serverPort != "80" && serverPort != "443" {
		input = fmt.Sprintf("test.example.com:%s[%s]", serverPort, serverIP)
	}

	results, err := testutils.RunHttpxAndGetResults(input, debug, "-vhost-input", "-json")
	if err != nil {
		return err
	}

	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}

	// Parse JSON output to verify the host was set correctly
	var jsonResult map[string]interface{}
	if err := json.Unmarshal([]byte(results[0]), &jsonResult); err != nil {
		return fmt.Errorf("failed to parse JSON output: %v", err)
	}

	// Verify that the request went to the correct IP
	if jsonResult["host"] != serverIP {
		return fmt.Errorf("expected host to be %s, got %v", serverIP, jsonResult["host"])
	}

	return nil
}

// Test vhost-input with proxy to ensure proxy bypass is fixed
type vhostWithProxy struct{}

func (v *vhostWithProxy) Execute() error {
	// Create a target server
	targetRouter := httprouter.New()
	targetRouter.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("X-Host-Header", r.Host)
		w.Header().Set("X-Target-Server", "true")
		fmt.Fprintf(w, "Target server - Host: %s", r.Host)
	}))
	targetServer := httptest.NewServer(targetRouter)
	defer targetServer.Close()

	// Create a proxy server that logs requests
	proxyRequests := make([]string, 0)
	proxyRouter := httprouter.New()
	proxyRouter.Handle("CONNECT", "/*path", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		proxyRequests = append(proxyRequests, fmt.Sprintf("CONNECT %s", r.Host))
		// Simple CONNECT proxy implementation
		w.WriteHeader(http.StatusOK)
	}))
	proxyRouter.NotFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests = append(proxyRequests, fmt.Sprintf("%s %s", r.Method, r.URL.String()))
		
		// For testing, we don't need to actually forward the request
		// Just return a mock response to avoid DNS lookup errors
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Proxy test response")
	})
	
	proxyServer := httptest.NewServer(proxyRouter)
	defer proxyServer.Close()

	// Extract IPs
	targetURL, _ := url.Parse(targetServer.URL)
	targetIP := strings.Split(targetURL.Host, ":")[0]
	targetPort := targetURL.Port()

	// Test HTTP vhost-input through proxy
	input := fmt.Sprintf("http://test.example.com[%s]", targetIP)
	if targetPort != "" && targetPort != "80" {
		input = fmt.Sprintf("http://test.example.com:%s[%s]", targetPort, targetIP)
	}

	_, err := testutils.RunHttpxAndGetResults(input, debug, 
		"-vhost-input", 
		"-proxy", proxyServer.URL,
		"-no-fallback-scheme",
		"-json")
	if err != nil {
		return err
	}

	// Verify that the proxy received the request
	if len(proxyRequests) == 0 {
		return fmt.Errorf("proxy bypass detected: no requests received by proxy")
	}

	// Verify the request went through the proxy
	foundProxyRequest := false
	for _, req := range proxyRequests {
		if strings.Contains(req, "test.example.com") {
			foundProxyRequest = true
			break
		}
	}
	
	if !foundProxyRequest {
		return fmt.Errorf("proxy bypass detected: request did not go through proxy")
	}

	return nil
}

// Test invalid vhost-input formats
type vhostInvalidFormat struct{}

func (v *vhostInvalidFormat) Execute() error {
	// Test various invalid formats
	invalidInputs := []string{
		"example.com[]",          // empty brackets
		"[93.184.216.34]",        // no hostname
		"example.com[invalid]",   // invalid IP
	}

	for _, input := range invalidInputs {
		results, err := testutils.RunHttpxAndGetResults(input, debug, "-vhost-input")
		// These should either fail or produce no output
		if err == nil && len(results) > 0 {
			// If we got results, verify they don't have CustomIP set
			for _, result := range results {
				if strings.Contains(result, "[") && strings.Contains(result, "]") {
					return fmt.Errorf("invalid vhost-input %s should not be processed", input)
				}
			}
		}
	}

	return nil
}

// Test multiple vhost-input targets
type vhostMultipleTargets struct{}

func (v *vhostMultipleTargets) Execute() error {
	// Create a test server
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "Host: %s", r.Host)
	}))
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Extract IP from the test server URL
	tsURL, _ := url.Parse(ts.URL)
	serverIP := strings.Split(tsURL.Host, ":")[0]
	serverPort := tsURL.Port()

	// Create multiple vhost inputs
	inputs := []string{
		fmt.Sprintf("test1.example.com[%s]", serverIP),
		fmt.Sprintf("test2.example.com[%s]", serverIP),
		fmt.Sprintf("http://test3.example.com[%s]", serverIP),
	}

	// Adjust for non-standard ports
	if serverPort != "" && serverPort != "80" && serverPort != "443" {
		inputs = []string{
			fmt.Sprintf("test1.example.com:%s[%s]", serverPort, serverIP),
			fmt.Sprintf("test2.example.com:%s[%s]", serverPort, serverIP),
			fmt.Sprintf("http://test3.example.com:%s[%s]", serverPort, serverIP),
		}
	}

	// Test with multiple inputs via stdin
	inputStr := strings.Join(inputs, "\n")
	results, err := testutils.RunHttpxBinaryAndGetResults(inputStr, "./httpx", debug, []string{"-vhost-input"})
	if err != nil {
		return err
	}

	// We should get at least one result (the test server responds to all vhosts)
	if len(results) == 0 {
		return fmt.Errorf("expected at least one result, got %d", len(results))
	}

	return nil
}