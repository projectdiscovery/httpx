package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/httpx/internal/testutils"
)

var httpTestcases = map[string]testutils.TestCase{
	"Standard HTTP GET Request":                                                 &standardHttpGet{},
	"Standard HTTPS GET Request":                                                &standardHttpGet{tls: true},
	"Raw HTTP GET Request":                                                      &standardHttpGet{unsafe: true},
	"Raw request with non standard rfc path via stdin":                          &standardHttpGet{unsafe: true, stdinPath: "/%invalid"},
	"Raw request with non standard rfc path via cli flag":                       &standardHttpGet{unsafe: true, path: "/%invalid"},
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/363": &issue363{}, // infinite redirect
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/276": &issue276{}, // full path with port in output
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/277": &issue277{}, // scheme://host:port via stdin
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/303": &issue303{}, // misconfigured gzip header with uncompressed body
}

type standardHttpGet struct {
	tls            bool
	unsafe         bool
	stdinPath      string
	path           string
	expectedOutput string
}

func (h *standardHttpGet) Execute() error {
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is a test")
		r.Close = true
	}))
	var ts *httptest.Server
	if h.tls {
		ts = httptest.NewTLSServer(router)
	} else {
		ts = httptest.NewServer(router)
	}
	defer ts.Close()
	var extra []string
	if h.unsafe {
		extra = append(extra, "-unsafe")
	}
	if h.path != "" {
		extra = append(extra, "-path", "\""+h.path+"\"")
	}

	URL := ts.URL
	if h.stdinPath != "" {
		URL += h.stdinPath
	}

	results, err := testutils.RunHttpxAndGetResults(URL, debug, extra...)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}

	if h.expectedOutput != "" && !strings.EqualFold(results[0], h.expectedOutput) {
		return errIncorrectResult(results[0], h.expectedOutput)
	}

	return nil
}

type issue276 struct{}

func (h *issue276) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.GET("/redirect", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Add("Location", ts.URL+"/redirect")
		w.WriteHeader(302)
		fmt.Fprintf(w, "<html><body><title>Object moved</title></body></html>")
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunHttpxAndGetResults(ts.URL+"/redirect", debug, "-status-code", "-title", "-no-color")
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	// check if we have all the items on the cli
	// full url with port
	// status code
	// title
	expected := ts.URL + "/redirect" + " [302] [Object moved]"
	if !strings.EqualFold(results[0], expected) {
		return errIncorrectResult(results[0], expected)
	}
	return nil
}

type issue277 struct{}

func (h *issue277) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.GET("/hpp", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		if p.ByName("pp") == `%22%3E%3Ch1%3Easdasd%3C%2Fh1%3E` {
			w.WriteHeader(http.StatusOK)
		}
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()
	uripath := "/hpp/?pp=%22%3E%3Ch1%3Easdasd%3C%2Fh1%3E"
	results, err := testutils.RunHttpxAndGetResults(ts.URL+uripath, debug)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	// check if we have all the items on the cli
	// full url with port
	// status code
	// title
	expected := ts.URL + uripath
	if !strings.EqualFold(results[0], expected) {
		return errIncorrectResult(results[0], expected)
	}
	return nil
}

type issue303 struct{}

func (h *issue303) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.GET("/hpp", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		// mimic a misconfigured web server behavior declaring gzip body
		w.Header().Add("Content-Encoding", "gzip")
		// but sending it uncompressed
		fmt.Fprint(w, "<html><body>This is a test</body></html>")
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunHttpxAndGetResults(ts.URL, debug)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	// check if we have all the items on the cli
	// full url with port
	expected := ts.URL
	if !strings.EqualFold(results[0], expected) {
		return errIncorrectResult(results[0], expected)
	}
	return nil
}

type issue363 struct{}

func (h *issue363) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.GET("/redirect", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Add("Location", ts.URL+"/redirect")
		w.WriteHeader(302)
		fmt.Fprintf(w, "<html><body><title>Object moved</title></body></html>")
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunHttpxAndGetResults(ts.URL+"/redirect", debug, "-no-color", "-follow-redirects")
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	return nil
}
