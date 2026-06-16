package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/microcosm-cc/bluemonday"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/httpx/common/httputilz"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/useragent"
	"github.com/projectdiscovery/utils/generic"
	pdhttputil "github.com/projectdiscovery/utils/http"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

// HTTPX represent an instance of the library client
type HTTPX struct {
	client        *http.Client
	client2       *http.Client
	clientRaw     http.RoundTripper
	Filters       []Filter
	Options       *Options
	htmlPolicy    *bluemonday.Policy
	CustomHeaders map[string][]string
	cdn           *cdncheck.Client
	Dialer        *fastdialer.Dialer
	NetworkPolicy *networkpolicy.NetworkPolicy
}

// New httpx instance
func New(options *Options) (*HTTPX, error) {
	httpx := &HTTPX{}
	fastdialerOpts := fastdialer.DefaultOptions

	// if the user specified any custom resolver disables system resolvers and syscall lookup fallback
	if len(options.Resolvers) > 0 {
		fastdialerOpts.ResolversFile = false
		fastdialerOpts.EnableFallback = false
	}

	if options.NetworkPolicy != nil {
		httpx.NetworkPolicy = options.NetworkPolicy
		fastdialerOpts.NetworkPolicy = options.NetworkPolicy
	}
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

	handleHSTS := func(req *http.Request) {
		if req.Response.Header.Get("Strict-Transport-Security") == "" {
			return
		}

		req.URL.Scheme = "https"
	}

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

			if options.RespectHSTS {
				handleHSTS(redirectedRequest)
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
			var newHost = redirectedRequest.URL.Hostname()
			var oldHost = previousRequests[0].URL.Hostname()
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

			if options.RespectHSTS {
				handleHSTS(redirectedRequest)
			}

			return nil
		}
	}
	if httpx.Options.HTTPProxy != "" {
		httpx.Options.Proxy = httpx.Options.HTTPProxy
	} else if httpx.Options.SocksProxy != "" {
		httpx.Options.Proxy = httpx.Options.SocksProxy
	}
	if httpx.Options.Proxy != "" {
		if _, parseErr := url.Parse(httpx.Options.Proxy); parseErr != nil {
			return nil, parseErr
		}
	}

	// reqx backs every request path except ZTLS: reqx has no zcrypto/ztls
	// handshake yet, so -ztls keeps using fastdialer's lenient DialTLS through
	// the net/http transport. The dedicated HTTP/2 probe client and the unsafe
	// (raw) client always use reqx. Retries are layered on the safe client via a
	// retry round tripper (replacing retryablehttp).
	var safeTransport http.RoundTripper
	if httpx.Options.ZTLS {
		safeTransport, err = newZTLSTransport(httpx.Dialer, httpx.Options)
		if err != nil {
			return nil, err
		}
	} else {
		safeTransport = newReqxTransport(httpx.Dialer, httpx.Options)
	}
	httpx.client = &http.Client{
		Transport:     newRetryRoundTripper(safeTransport, httpx.Options.RetryMax),
		Timeout:       httpx.Options.Timeout,
		CheckRedirect: redirectFunc,
	}

	httpx.client2 = &http.Client{
		Transport: newReqxHTTP2Transport(httpx.Dialer, httpx.Options),
		Timeout:   httpx.Options.Timeout,
	}

	httpx.clientRaw = newReqxRawTransport(httpx.Dialer, httpx.Options)

	httpx.htmlPolicy = bluemonday.NewPolicy()
	httpx.CustomHeaders = httpx.Options.CustomHeaders

	if options.CDNCheckClient != nil {
		httpx.cdn = options.CDNCheckClient
	} else {
		if options.CdnCheck != "false" || options.ExcludeCdn {
			httpx.cdn = cdncheck.New()
		}
	}

	return httpx, nil
}

// Do http request
func (h *HTTPX) Do(req *http.Request, unsafeOptions UnsafeOptions) (*Response, error) {
	timeStart := time.Now()

	var gzipRetry bool
get_response:
	httpresp, err := h.getResponse(req, unsafeOptions)
	if httpresp == nil && err != nil {
		return nil, err
	}

	// Some transports (e.g. reqx TLS impersonation) may not populate
	// Response.Request; ensure it is set so downstream redirect-chain
	// extraction and request dumps don't dereference a nil request.
	if httpresp != nil && httpresp.Request == nil {
		httpresp.Request = req
	}

	var shouldIgnoreErrors, shouldIgnoreBodyErrors bool
	if h.Options.Unsafe && req.Method == http.MethodHead && err != nil &&
		!stringsutil.ContainsAny(err.Error(), "i/o timeout") {
		shouldIgnoreErrors = true
		shouldIgnoreBodyErrors = true
	}

	var resp Response
	resp.Input = req.Host

	resp.Headers = httpresp.Header.Clone()

	if h.Options.MaxResponseBodySizeToRead > 0 {
		httpresp.Body = io.NopCloser(io.LimitReader(httpresp.Body, h.Options.MaxResponseBodySizeToRead))
		defer func() {
			_, _ = io.Copy(io.Discard, httpresp.Body)
			_ = httpresp.Body.Close()
		}()
	}

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
		return nil, err
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
			if contentLengthInt, err := strconv.Atoi(contentLength[0]); err == nil {
				resp.ContentLength = contentLengthInt
			}
		}

		// if we have a body, then use the number of bytes in the body if the length is still zero
		if resp.ContentLength <= 0 && len(respbody) > 0 {
			resp.ContentLength = len(respbody)
		}
	}

	resp.Data = respbody

	// fill metrics
	resp.StatusCode = httpresp.StatusCode
	if respbodystr != "" {
		// number of words
		resp.Words = len(strings.Split(respbodystr, " "))
		// number of lines
		resp.Lines = len(strings.Split(strings.TrimSpace(respbodystr), "\n"))
	}

	if !h.Options.Unsafe && h.Options.TLSGrab {
		if h.Options.ZTLS {
			resp.TLSData = h.ZTLSGrab(httpresp)
		} else {
			// extracts TLS data if any
			resp.TLSData = h.TLSGrab(httpresp)
		}
	}

	if h.Options.ExtractFqdn {
		resp.CSPData = h.CSPGrab(&resp)
		resp.BodyDomains = h.BodyDomainGrab(&resp)
	}

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
func (h *HTTPX) getResponse(req *http.Request, unsafeOptions UnsafeOptions) (resp *http.Response, err error) {
	if h.Options.Unsafe {
		return h.doUnsafeWithOptions(req, unsafeOptions)
	}
	return h.client.Do(req)
}

// rawUnsafeMaxRedirects mirrors rawhttp.DefaultOptions.MaxRedirects.
const rawUnsafeMaxRedirects = 10

// isRawRedirect mirrors rawhttp's client Status.IsRedirect: any 3xx except 304.
func isRawRedirect(code int) bool {
	if code == http.StatusNotModified {
		return false
	}
	return code >= http.StatusMultipleChoices && code < http.StatusBadRequest
}

// doUnsafeWithOptions performs an unsafe (wire-level) request via the reqx raw
// engine. reqx's raw mode sends the request line verbatim (no URL
// normalization) while retaining rawhttp-equivalent automatic Host and
// Content-Length behavior.
//
// It follows redirects the same way as the legacy rawhttp path: preserving the
// method, headers and custom URI path across hops, resolving root-relative
// Location values against the current scheme/host, up to rawUnsafeMaxRedirects.
func (h *HTTPX) doUnsafeWithOptions(req *http.Request, unsafeOptions UnsafeOptions) (*http.Response, error) {
	header := req.Header.Clone()
	host := req.Host
	target := req.URL.String()
	body := req.Body

	current := 0
	for {
		hreq, err := http.NewRequestWithContext(req.Context(), req.Method, target, body)
		if err != nil {
			return nil, err
		}
		hreq.Header = header.Clone()
		if host != "" {
			hreq.Host = host
		}
		// send the URI path exactly as provided (no normalization) via Opaque
		if unsafeOptions.URIPath != "" {
			hreq.URL.Opaque = unsafeOptions.URIPath
		}

		resp, err := h.clientRaw.RoundTrip(hreq)
		if err != nil {
			return nil, err
		}

		if !isRawRedirect(resp.StatusCode) || current > rawUnsafeMaxRedirects {
			return resp, nil
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return resp, nil
		}
		// drain and close the intermediate response body
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if strings.HasPrefix(loc, "/") {
			loc = fmt.Sprintf("%s://%s%s", hreq.URL.Scheme, hreq.URL.Host, loc)
		}
		target = loc
		// the body reader is consumed after the first write (matches rawhttp)
		body = nil
		current++
	}
}

// Verify the http calls and apply-cascade all the filters, as soon as one matches it returns true
func (h *HTTPX) Verify(req *http.Request, unsafeOptions UnsafeOptions) (bool, error) {
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
func (h *HTTPX) NewRequest(method, targetURL string) (req *http.Request, err error) {
	return h.NewRequestWithContext(context.Background(), method, targetURL)
}

// NewRequest from url
func (h *HTTPX) NewRequestWithContext(ctx context.Context, method, targetURL string) (req *http.Request, err error) {
	urlx, err := urlutil.ParseURL(targetURL, h.Options.Unsafe)
	if err != nil {
		return nil, err
	}

	// we provide a url without path to http.NewRequest and then replace the URL
	// instance directly: http.NewRequest internally parses with url.Parse which
	// would otherwise drop the patches urlutil.URL applies in unsafe mode
	// (e.g. https://scanme.sh/%invalid). Only u.Host is read by net/http; the
	// rest of the request URL is carried by the url.URL instance we assign.
	req, err = http.NewRequestWithContext(ctx, method, "https://"+urlx.Host, nil)
	if err != nil {
		return nil, err
	}
	urlx.Update()
	req.URL = urlx.URL
	if req.URL.Host != "" && req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}

	// Skip if unsafe is used
	if !h.Options.Unsafe {
		// set default user agent
		req.Header.Set("User-Agent", h.Options.DefaultUserAgent)
		// set default encoding to accept utf8
		req.Header.Add("Accept-Charset", "utf-8")
	}

	// attach httptrace collection when tracing is enabled
	if h.Options.Trace {
		req = withTrace(req)
	}
	return
}

// SetCustomHeaders on the provided request
func (h *HTTPX) SetCustomHeaders(r *http.Request, headers map[string][]string) {
	// Coalesce values by canonical header key first. net/http canonicalizes keys
	// on Del/Add, so case-variant duplicates (e.g. "X-Test" and "x-test") would
	// otherwise have the second key's Del wipe the values added for the first.
	normalized := make(map[string][]string, len(headers))
	for name, values := range headers {
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		normalized[canonical] = append(normalized[canonical], values...)
	}

	for name, values := range normalized {
		r.Header.Del(name)
		for _, value := range values {
			switch strings.ToLower(name) {
			case "host":
				r.Host = value
				if h.Options.Unsafe {
					r.Header.Add("Host", value)
				}
			case "cookie":
				// cookies are set in the default branch, and reset during the follow redirect flow
				fallthrough
			default:
				r.Header.Add(name, value)
			}
		}
	}
	if h.Options.RandomAgent {
		userAgent := useragent.PickRandom()
		r.Header.Set("User-Agent", userAgent.Raw) //nolint
	}
	if h.Options.AutoReferer && r.Header.Get("Referer") == "" {
		r.Header.Set("Referer", r.URL.String())
	}
}

func (httpx *HTTPX) setCustomCookies(req *http.Request) {
	if httpx.Options.hasCustomCookies() {
		for _, cookie := range httpx.Options.customCookies {
			req.AddCookie(cookie)
		}
	}
}

func (httpx *HTTPX) Sanitize(respStr string, trimLine, normalizeSpaces bool) string {
	respStr = httpx.htmlPolicy.Sanitize(respStr)
	if trimLine {
		respStr = strings.ReplaceAll(respStr, "\n", "")
	}
	if normalizeSpaces {
		respStr = httputilz.NormalizeSpaces(respStr)
	}
	return respStr
}
