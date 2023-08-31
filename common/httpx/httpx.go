package httpx

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/corpix/uarand"
	"github.com/microcosm-cc/bluemonday"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/rawhttp"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/generic"
	pdhttputil "github.com/projectdiscovery/utils/http"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
)

// HTTPX represent an instance of the library client
type HTTPX struct {
	client        *retryablehttp.Client
	client2       *http.Client
	Filters       []Filter
	Options       *Options
	htmlPolicy    *bluemonday.Policy
	CustomHeaders map[string]string
	cdn           *cdncheck.Client
	Dialer        *fastdialer.Dialer
}

// New httpx instance
func New(options *Options) (*HTTPX, error) {
	httpx := &HTTPX{}
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.Deny = options.Deny
	fastdialerOpts.Allow = options.Allow
	fastdialerOpts.WithDialerHistory = true
	fastdialerOpts.WithZTLS = options.ZTLS
	if len(options.Resolvers) > 0 {
		fastdialerOpts.BaseResolvers = options.Resolvers
	}
	fastdialerOpts.SNIName = options.SniName
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		return nil, fmt.Errorf("could not create resolver cache: %s", err)
	}
	httpx.Dialer = dialer

	httpx.Options = options

	httpx.Options.parseCustomCookies()

	var retryablehttpOptions = retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.Timeout = httpx.Options.Timeout
	retryablehttpOptions.RetryMax = httpx.Options.RetryMax

	var redirectFunc = func(_ *http.Request, _ []*http.Request) error {
		// Tell the http client to not follow redirect
		return http.ErrUseLastResponse
	}

	if httpx.Options.FollowRedirects {
		// Follow redirects up to a maximum number
		redirectFunc = func(redirectedRequest *http.Request, previousRequests []*http.Request) error {
			// add custom cookies if necessary
			httpx.setCustomCookies(redirectedRequest)
			if len(previousRequests) >= options.MaxRedirects {
				// https://github.com/golang/go/issues/10069
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	if httpx.Options.FollowHostRedirects {
		// Only follow redirects on the same host up to a maximum number
		redirectFunc = func(redirectedRequest *http.Request, previousRequests []*http.Request) error {
			// add custom cookies if necessary
			httpx.setCustomCookies(redirectedRequest)

			// Check if we get a redirect to a different host
			var newHost = redirectedRequest.URL.Host
			var oldHost = previousRequests[0].Host
			if oldHost == "" {
				oldHost = previousRequests[0].URL.Host
			}
			if newHost != oldHost {
				// Tell the http client to not follow redirect
				return http.ErrUseLastResponse
			}
			if len(previousRequests) >= options.MaxRedirects {
				// https://github.com/golang/go/issues/10069
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	transport := &http.Transport{
		DialContext: httpx.Dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if options.TlsImpersonate {
				return httpx.Dialer.DialTLSWithConfigImpersonate(ctx, network, addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, impersonate.Random, nil)
			}
			return httpx.Dialer.DialTLS(ctx, network, addr)
		},
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}

	if httpx.Options.SniName != "" {
		transport.TLSClientConfig.ServerName = httpx.Options.SniName
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

	transport2 := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		AllowHTTP: true,
	}
	if httpx.Options.SniName != "" {
		transport2.TLSClientConfig.ServerName = httpx.Options.SniName
	}
	httpx.client2 = &http.Client{
		Transport: transport2,
		Timeout:   httpx.Options.Timeout,
	}

	httpx.htmlPolicy = bluemonday.NewPolicy()
	httpx.CustomHeaders = httpx.Options.CustomHeaders
	if options.CdnCheck || options.ExcludeCdn {
		httpx.cdn = cdncheck.New()
	}

	return httpx, nil
}

// Do http request
func (h *HTTPX) Do(req *retryablehttp.Request, unsafeOptions UnsafeOptions) (*Response, error) {
	timeStart := time.Now()

	var gzipRetry bool
get_response:
	httpresp, err := h.getResponse(req, unsafeOptions)
	if httpresp == nil && err != nil {
		return nil, err
	}

	var shouldIgnoreErrors, shouldIgnoreBodyErrors bool
	switch {
	case h.Options.Unsafe && req.Method == http.MethodHead && !stringsutil.ContainsAny(err.Error(), "i/o timeout"):
		shouldIgnoreErrors = true
		shouldIgnoreBodyErrors = true
	}

	var resp Response

	resp.Headers = httpresp.Header.Clone()

	// httputil.DumpResponse does not handle websockets
	headers, rawResp, err := pdhttputil.DumpResponseHeadersAndRaw(httpresp)
	if err != nil {
		if stringsutil.ContainsAny(err.Error(), "tls: user canceled") {
			shouldIgnoreErrors = true
			shouldIgnoreBodyErrors = true
		}

		// Edge case - some servers respond with gzip encoding header but uncompressed body, in this case the standard library configures the reader as gzip, triggering an error when read.
		// The bytes slice is not accessible because of abstraction, therefore we need to perform the request again tampering the Accept-Encoding header
		if !gzipRetry && strings.Contains(err.Error(), "gzip: invalid header") {
			gzipRetry = true
			req.Header.Set("Accept-Encoding", "identity")
			goto get_response
		}
		if !shouldIgnoreErrors {
			return nil, err
		}
	}
	resp.Raw = string(rawResp)
	resp.RawHeaders = string(headers)
	var respbody []byte
	// body shouldn't be read with the following status codes
	// 101 - Switching Protocols => websockets don't have a readable body
	// 304 - Not Modified => no body the response terminates with latest header newline
	if !generic.EqualsAny(httpresp.StatusCode, http.StatusSwitchingProtocols, http.StatusNotModified) {
		var err error
		respbody, err = io.ReadAll(io.LimitReader(httpresp.Body, h.Options.MaxResponseBodySizeToRead))
		if err != nil && !shouldIgnoreBodyErrors {
			return nil, err
		}
	}

	closeErr := httpresp.Body.Close()
	if closeErr != nil && !shouldIgnoreBodyErrors {
		return nil, closeErr
	}

	// Todo: replace with https://github.com/projectdiscovery/utils/issues/110
	resp.RawData = make([]byte, len(respbody))
	copy(resp.RawData, respbody)

	respbody, err = DecodeData(respbody, httpresp.Header)
	if err != nil && !shouldIgnoreBodyErrors {
		return nil, closeErr
	}

	respbodystr := string(respbody)

	// check if we need to strip html
	if h.Options.VHostStripHTML {
		respbodystr = h.htmlPolicy.Sanitize(respbodystr)
	}

	// if content length is not defined
	if resp.ContentLength <= 0 {
		// check if it's in the header and convert to int
		if contentLength, ok := resp.Headers["Content-Length"]; ok && len(contentLength) > 0 {
			contentLengthInt, _ := strconv.Atoi(contentLength[0])
			resp.ContentLength = contentLengthInt
		}

		// if we have a body, then use the number of bytes in the body if the length is still zero
		if resp.ContentLength <= 0 && len(respbody) > 0 {
			resp.ContentLength = len(respbody)
		}
	}

	resp.Data = respbody

	// fill metrics
	resp.StatusCode = httpresp.StatusCode
	// number of words
	resp.Words = len(strings.Split(respbodystr, " "))
	// number of lines
	resp.Lines = len(strings.Split(respbodystr, "\n"))

	if !h.Options.Unsafe && h.Options.TLSGrab {
		if h.Options.ZTLS {
			resp.TLSData = h.ZTLSGrab(httpresp)
		} else {
			// extracts TLS data if any
			resp.TLSData = h.TLSGrab(httpresp)
		}
	}

	resp.CSPData = h.CSPGrab(&resp)

	// build the redirect flow by reverse cycling the response<-request chain
	if !h.Options.Unsafe {
		chain, err := pdhttputil.GetChain(httpresp)
		if err != nil {
			return nil, err
		}
		resp.Chain = chain
	}

	resp.Duration = time.Since(timeStart)

	return &resp, nil
}

// RequestOverride contains the URI path to override the request
type UnsafeOptions struct {
	URIPath string
}

// getResponse returns response from safe / unsafe request
func (h *HTTPX) getResponse(req *retryablehttp.Request, unsafeOptions UnsafeOptions) (resp *http.Response, err error) {
	if h.Options.Unsafe {
		return h.doUnsafeWithOptions(req, unsafeOptions)
	}
	return h.client.Do(req)
}

// doUnsafe does an unsafe http request
func (h *HTTPX) doUnsafeWithOptions(req *retryablehttp.Request, unsafeOptions UnsafeOptions) (*http.Response, error) {
	method := req.Method
	headers := req.Header
	targetURL := req.URL.String()
	body := req.Body
	options := rawhttp.DefaultOptions
	options.Timeout = h.Options.Timeout
	return rawhttp.DoRawWithOptions(method, targetURL, unsafeOptions.URIPath, headers, body, options)
}

// Verify the http calls and apply-cascade all the filters, as soon as one matches it returns true
func (h *HTTPX) Verify(req *retryablehttp.Request, unsafeOptions UnsafeOptions) (bool, error) {
	resp, err := h.Do(req, unsafeOptions)
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
	return h.NewRequestWithContext(context.Background(), method, targetURL)
}

// NewRequest from url
func (h *HTTPX) NewRequestWithContext(ctx context.Context, method, targetURL string) (req *retryablehttp.Request, err error) {
	urlx, err := urlutil.ParseURL(targetURL, h.Options.Unsafe)
	if err != nil {
		return nil, err
	}

	req, err = retryablehttp.NewRequestFromURLWithContext(ctx, method, urlx, nil)
	if err != nil {
		return nil, err
	}
	// Skip if unsafe is used
	if !h.Options.Unsafe {
		// set default user agent
		req.Header.Set("User-Agent", h.Options.DefaultUserAgent)
		// set default encoding to accept utf8
		req.Header.Add("Accept-Charset", "utf-8")
	}
	return
}

// SetCustomHeaders on the provided request
func (h *HTTPX) SetCustomHeaders(r *retryablehttp.Request, headers map[string]string) {
	for name, value := range headers {
		switch strings.ToLower(name) {
		case "host":
			r.Host = value
		case "cookie":
			// cookies are set in the default branch, and reset during the follow redirect flow
			fallthrough
		default:
			r.Header.Set(name, value)
		}
	}
	if h.Options.RandomAgent {
		r.Header.Set("User-Agent", uarand.GetRandom()) //nolint
	}
}

func (httpx *HTTPX) setCustomCookies(req *http.Request) {
	if httpx.Options.hasCustomCookies() {
		for _, cookie := range httpx.Options.customCookies {
			req.AddCookie(cookie)
		}
	}
}
