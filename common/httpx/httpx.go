package httpx

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/microcosm-cc/bluemonday"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/httpx/common/cache"
	"github.com/projectdiscovery/httpx/common/httputilz"
	"github.com/projectdiscovery/rawhttp"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/net/http2"
)

// HTTPX represent an instance of the library client
type HTTPX struct {
	client          *retryablehttp.Client
	client2         *http.Client
	Filters         []Filter
	Options         *Options
	htmlPolicy      *bluemonday.Policy
	CustomHeaders   map[string]string
	RequestOverride *RequestOverride
	cdn             *cdncheck.Client
}

// New httpx instance
func New(options *Options) (*HTTPX, error) {
	httpx := &HTTPX{}
	dialer, err := cache.NewDialer(cache.DefaultOptions)
	if err != nil {
		return nil, fmt.Errorf("could not create resolver cache: %s", err)
	}

	httpx.Options = options

	var retryablehttpOptions = retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.Timeout = httpx.Options.Timeout
	retryablehttpOptions.RetryMax = httpx.Options.RetryMax

	var redirectFunc = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse // Tell the http client to not follow redirect
	}

	if httpx.Options.FollowRedirects {
		// Follow redirects
		redirectFunc = nil
	}

	if httpx.Options.FollowHostRedirects {
		// Only follow redirects on the same host
		redirectFunc = func(redirectedRequest *http.Request, previousRequest []*http.Request) error { // timo
			// Check if we get a redirect to a differen host
			var newHost = redirectedRequest.URL.Host
			var oldHost = previousRequest[0].URL.Host
			if newHost != oldHost {
				return http.ErrUseLastResponse // Tell the http client to not follow redirect
			}
			return nil
		}
	}

	transport := &http.Transport{
		DialContext:         dialer,
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}

	if httpx.Options.HTTPProxy != "" {
		proxyURL, parseErr := url.Parse(httpx.Options.HTTPProxy)
		if parseErr != nil {
			return nil, parseErr
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	httpx.client = retryablehttp.NewWithHTTPClient(&http.Client{
		Transport:     transport,
		Timeout:       httpx.Options.Timeout,
		CheckRedirect: redirectFunc,
	}, retryablehttpOptions)

	httpx.client2 = &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			AllowHTTP: true,
		},
		Timeout: httpx.Options.Timeout,
	}

	httpx.htmlPolicy = bluemonday.NewPolicy()
	httpx.CustomHeaders = httpx.Options.CustomHeaders
	httpx.RequestOverride = &options.RequestOverride
	if options.CdnCheck {
		httpx.cdn, err = cdncheck.NewWithCache()
		if err != nil {
			return nil, fmt.Errorf("could not create cdn check: %s", err)
		}
	}

	return httpx, nil
}

// Do http request
func (h *HTTPX) Do(req *retryablehttp.Request) (*Response, error) {
	timeStart := time.Now()

	httpresp, err := h.getResponse(req)
	if err != nil {
		return nil, err
	}

	var resp Response

	resp.Headers = httpresp.Header.Clone()

	// httputil.DumpResponse does not handle websockets
	rawresp, err := httputilz.DumpResponse(httpresp)
	if err != nil {
		return nil, err
	}

	resp.Raw = rawresp

	var respbody []byte
	// websockets don't have a readable body
	if httpresp.StatusCode != http.StatusSwitchingProtocols {
		var err error
		respbody, err = ioutil.ReadAll(httpresp.Body)
		if err != nil {
			return nil, err
		}
	}

	closeErr := httpresp.Body.Close()
	if closeErr != nil {
		return nil, closeErr
	}

	respbodystr := string(respbody)

	// check if we need to strip html
	if h.Options.VHostStripHTML {
		respbodystr = h.htmlPolicy.Sanitize(respbodystr)
	}

	resp.ContentLength = utf8.RuneCountInString(respbodystr)
	resp.Data = respbody

	// fill metrics
	resp.StatusCode = httpresp.StatusCode
	// number of words
	resp.Words = len(strings.Split(respbodystr, " "))
	// number of lines
	resp.Lines = len(strings.Split(respbodystr, "\n"))

	if !h.Options.Unsafe {
		// extracts TLS data if any
		resp.TLSData = h.TLSGrab(httpresp)
	}

	resp.CSPData = h.CSPGrab(httpresp)
	resp.Duration = time.Since(timeStart)

	return &resp, nil
}

// RequestOverride contains the URI path to override the request
type RequestOverride struct {
	URIPath string
}

// getResponse returns response from safe / unsafe request
func (h *HTTPX) getResponse(req *retryablehttp.Request) (*http.Response, error) {
	if h.Options.Unsafe {
		return h.doUnsafe(req)
	}

	return h.client.Do(req)
}

// doUnsafe does an unsafe http request
func (h *HTTPX) doUnsafe(req *retryablehttp.Request) (*http.Response, error) {
	method := req.Method
	headers := req.Header
	targetURL := req.URL.String()
	body := req.Body
	return rawhttp.DoRaw(method, targetURL, h.RequestOverride.URIPath, headers, body)
}

// Verify the http calls and apply-cascade all the filters, as soon as one matches it returns true
func (h *HTTPX) Verify(req *retryablehttp.Request) (bool, error) {
	resp, err := h.Do(req)
	if err != nil {
		return false, err
	}

	// apply all filters
	for _, f := range h.Filters {
		ok, err := f.Filter(resp)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
}

// AddFilter cascade
func (h *HTTPX) AddFilter(f Filter) {
	h.Filters = append(h.Filters, f)
}

// NewRequest from url
func (h *HTTPX) NewRequest(method, targetURL string) (req *retryablehttp.Request, err error) {
	req, err = retryablehttp.NewRequest(method, targetURL, nil)
	if err != nil {
		return
	}

	// set default user agent
	req.Header.Set("User-Agent", h.Options.DefaultUserAgent)
	// set default encoding to accept utf8
	req.Header.Add("Accept-Charset", "utf-8")
	return
}

// SetCustomHeaders on the provided request
func (h *HTTPX) SetCustomHeaders(r *retryablehttp.Request, headers map[string]string) {
	for name, value := range headers {
		r.Header.Set(name, value)
		// host header is particular
		if strings.EqualFold(name, "host") {
			r.Host = value
		}
	}
}
