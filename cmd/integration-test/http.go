package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/httpx/internal/testutils"
	fileutil "github.com/projectdiscovery/utils/file"
)

var httpTestcases = map[string]testutils.TestCase{
	"Standard HTTP GET Request":                                                           &standardHttpGet{},
	"Standard HTTPS GET Request":                                                          &standardHttpGet{tls: true},
	"Raw HTTP GET Request":                                                                &standardHttpGet{unsafe: true},
	"Raw request with non standard rfc path via stdin":                                    &standardHttpGet{unsafe: true, stdinPath: "/%invalid"},
	"Raw request with non standard rfc path via cli flag":                                 &standardHttpGet{unsafe: true, path: "/%invalid"},
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/363":           &issue363{}, // infinite redirect
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/276":           &issue276{}, // full path with port in output
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/277":           &issue277{}, // scheme://host:port via stdin
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/303":           &issue303{}, // misconfigured gzip header with uncompressed body
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/400":           &issue400{}, // post operation with body
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/414":           &issue414{}, // stream mode with path
	"Regression test for: https://github.com/projectdiscovery/httpx/issues/433":           &issue433{}, // new line scanning with title flag
	"Request URI to existing file - https://github.com/projectdiscovery/httpx/issues/480": &issue480{}, // request uri pointing to existing file
	"Standard HTTP GET Request with match response time":                                  &standardHttpGet{mrt: true, inputValue: "\"<10s\""},
	"Standard HTTP GET Request with filter response time":                                 &standardHttpGet{frt: true, inputValue: "\">3ms\""},
	"Multiple Custom Header":                                                              &customHeader{inputData: []string{"-debug-req", "-H", "'user-agent: test'", "-H", "'foo: bar'"}, expectedOutput: []string{"User-Agent: test", "Foo: bar"}},
	"Output Match Condition":                                                              &outputMatchCondition{inputData: []string{"-silent", "-mdc", "\"status_code == 200\""}},
	"Output Filter Condition":                                                             &outputFilterCondition{inputData: []string{"-silent", "-fdc", "\"status_code == 400\""}},
	"Output All":                                                                          &outputAll{},
}

type standardHttpGet struct {
	tls            bool
	unsafe         bool
	mrt            bool
	frt            bool
	inputValue     string
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
	if h.mrt {
		extra = append(extra, "-mrt", h.inputValue)
	}
	if h.frt {
		extra = append(extra, "-frt", h.inputValue)
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
		return errIncorrectResult(h.expectedOutput, results[0])
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
		return errIncorrectResult(expected, results[0])
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
		return errIncorrectResult(expected, results[0])
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
		return errIncorrectResult(expected, results[0])
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

type issue400 struct{}

func (h *issue400) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.POST("/receive", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("Content-Type", "application/json")
		data, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "data received %s", data)
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunHttpxAndGetResults(ts.URL+"/receive", debug, "-body 'a=b'", "-x POST", "-status-code")
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	return nil
}

type issue414 struct{}

func (h *issue414) Execute() error {
	var ts *httptest.Server
	uripath := "/path"
	router := httprouter.New()
	router.POST(uripath, httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("Content-Type", "application/json")
		data, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "data received %s", data)
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunHttpxAndGetResults(ts.URL, debug, fmt.Sprintf("-path '%s'", uripath))
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	expected := ts.URL + uripath
	if !strings.EqualFold(results[0], expected) {
		return errIncorrectResult(expected, results[0])
	}
	return nil
}

type issue433 struct{}

func (h *issue433) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	uriPath := "/index"
	router.GET(uriPath, httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		htmlResponse := "<html><head><title>Project\n\r Discovery\n - Httpx></title></head><body>test data</body></html>"
		fmt.Fprint(w, htmlResponse)
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunHttpxAndGetResults(fmt.Sprint(ts.URL, uriPath), debug, "-title", "-no-color")
	if err != nil {
		return err
	}
	if strings.Contains(results[0], "\n") {
		return errIncorrectResultsCount(results)
	}
	if strings.Contains(results[0], "\r") {
		return errIncorrectResultsCount(results)
	}
	return nil
}

type issue480 struct{}

func (h *issue480) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	uriPath := "////////////////../../../../../../../../etc/passwd"
	router.GET(uriPath, httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		htmlResponse := "<html><body>ok from uri</body></html>"
		fmt.Fprint(w, htmlResponse)
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunHttpxAndGetResults(ts.URL, debug, "-path", "////////////////../../../../../../../../etc/passwd")
	if err != nil {
		return err
	}
	if !strings.Contains(results[0], uriPath) {
		return errIncorrectResultsCount(results)
	}
	return nil
}

type customHeader struct {
	inputData      []string
	expectedOutput []string
}

func (h *customHeader) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprint(w, `{"status": "ok"}`)
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunHttpxAndGetCombinedResults(ts.URL, true, h.inputData...)
	if err != nil {
		return err
	}
	for _, expected := range h.expectedOutput {
		if !strings.Contains(results, expected) {
			return errIncorrectResult(expected, results)
		}
	}
	return nil
}

type outputMatchCondition struct {
	inputData []string
}

func (h *outputMatchCondition) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status": "ok"}`)
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunHttpxAndGetResults(ts.URL, false, h.inputData...)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	return nil
}

type outputFilterCondition struct {
	inputData []string
}

func (h *outputFilterCondition) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status": "ok"}`)
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunHttpxAndGetResults(ts.URL, false, h.inputData...)
	if err != nil {
		return err
	}

	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	return nil
}

type outputAll struct {
}

func (h *outputAll) Execute() error {
	var ts *httptest.Server
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status": "ok"}`)
	}))
	ts = httptest.NewServer(router)
	defer ts.Close()

	fileName := "test_output_all"
	_, hErr := testutils.RunHttpxAndGetResults(ts.URL, false, []string{"-o", fileName, "-oa"}...)
	if hErr != nil {
		return hErr
	}

	expectedFiles := []string{fileName, fileName + ".json", fileName + ".csv"}
	var actualFiles []string

	for _, file := range expectedFiles {
		if fileutil.FileExists(file) {
			actualFiles = append(actualFiles, file)
		}
	}
	if len(actualFiles) != 3 {
		return errIncorrectResultsCount(actualFiles)
	}

	for _, file := range actualFiles {
		_ = os.Remove(file)
	}

	return nil
}
