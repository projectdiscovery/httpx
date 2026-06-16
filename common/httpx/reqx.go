package httpx

import (
	"crypto/tls"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/reqx"
)

// proxyFromOptions resolves the effective proxy URL from the options.
func proxyFromOptions(options *Options) string {
	if options.HTTPProxy != "" {
		return options.HTTPProxy
	}
	if options.SocksProxy != "" {
		return options.SocksProxy
	}
	return options.Proxy
}

// impersonationProfiles is the set of reqx browser profiles used to satisfy
// the -tls-impersonate option (a randomized JA3/JA4 + HTTP/2 fingerprint).
var impersonationProfiles = []reqx.BrowserProfile{
	reqx.ProfileChrome131,
	reqx.ProfileChrome132,
	reqx.ProfileFirefox133,
	reqx.ProfileFirefoxESR,
	reqx.ProfileSafari18,
	reqx.ProfileEdge131,
	reqx.ProfileBrave,
}

func randomBrowserProfile() reqx.BrowserProfile {
	return impersonationProfiles[rand.Intn(len(impersonationProfiles))]
}

// newReqxTransport builds the reqx.Transport that backs the safe request path.
// fastdialer is preserved as the dialer so DNS caching, dial history and
// network policy keep working; TLS is performed by reqx so response.TLS (and
// therefore TLSGrab) is populated. HTTP/1.1 is forced to match the historical
// httpx client, except under impersonation where a full browser profile
// (TLS + HTTP/2 + header fingerprint) is applied instead.
func newReqxTransport(dialer *fastdialer.Dialer, options *Options) http.RoundTripper {
	opts := []reqx.Option{
		reqx.WithDialer(reqx.DialerFunc(dialer.Dial)),
		reqx.WithInsecureSkipVerify(),
		reqx.WithTLSMinVersion(tls.VersionTLS10),
		reqx.WithKeepAlive(false),
		reqx.WithTimeout(options.Timeout),
	}

	if options.TlsImpersonate {
		opts = append(opts, reqx.WithBrowserProfile(randomBrowserProfile()))
	} else {
		opts = append(opts, reqx.WithForceHTTP1())
	}

	if options.SniName != "" {
		opts = append(opts, reqx.WithSNI(options.SniName))
	}
	if proxy := proxyFromOptions(options); proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			opts = append(opts, reqx.WithProxyURL(u))
		}
	}

	return reqx.NewTransport(opts...)
}

// newReqxRawTransport builds a reqx.Transport that uses the wire-level raw
// engine for unsafe requests (replacing rawhttp). Disabling URL encoding routes
// requests through reqx's raw engine (sending the request line verbatim) while
// keeping rawhttp-equivalent automatic Host and Content-Length behavior.
func newReqxRawTransport(dialer *fastdialer.Dialer, options *Options) http.RoundTripper {
	opts := []reqx.Option{
		reqx.WithDialer(reqx.DialerFunc(dialer.Dial)),
		reqx.WithInsecureSkipVerify(),
		reqx.WithTLSMinVersion(tls.VersionTLS10),
		reqx.WithKeepAlive(false),
		reqx.WithForceHTTP1(),
		reqx.WithTimeout(options.Timeout),
		// route through reqx's raw engine without disabling auto Host /
		// Content-Length (mirrors rawhttp's AutomaticHostHeader / AutomaticContentLength)
		reqx.WithURLEncoding(false),
		// rawhttp does not inject Accept-Encoding; keep parity
		reqx.WithAutoAcceptEncoding(false),
	}
	if options.SniName != "" {
		opts = append(opts, reqx.WithSNI(options.SniName))
	}
	if proxy := proxyFromOptions(options); proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			opts = append(opts, reqx.WithProxyURL(u))
		}
	}
	return reqx.NewTransport(opts...)
}

// newReqxHTTP2Transport builds a reqx.Transport that negotiates HTTP/2, used by
// the dedicated client that probes for HTTP/2 support (replacing
// golang.org/x/net/http2.Transport) while keeping fastdialer as the dialer.
func newReqxHTTP2Transport(dialer *fastdialer.Dialer, options *Options) http.RoundTripper {
	opts := []reqx.Option{
		reqx.WithDialer(reqx.DialerFunc(dialer.Dial)),
		reqx.WithInsecureSkipVerify(),
		reqx.WithTLSMinVersion(tls.VersionTLS10),
		reqx.WithForceHTTP2(),
		reqx.WithTimeout(options.Timeout),
	}
	if options.SniName != "" {
		opts = append(opts, reqx.WithSNI(options.SniName))
	}
	return reqx.NewTransport(opts...)
}

// retryRoundTripper wraps an http.RoundTripper and retries transient failures,
// replacing the retry loop previously provided by retryablehttp. It mirrors the
// "spraying" defaults: exponential backoff between waitMin and waitMax, retrying
// on connection errors, 429 and 5xx (except 501).
type retryRoundTripper struct {
	next       http.RoundTripper
	maxRetries int
	waitMin    time.Duration
	waitMax    time.Duration
}

func newRetryRoundTripper(next http.RoundTripper, maxRetries int) *retryRoundTripper {
	return &retryRoundTripper{
		next:       next,
		maxRetries: maxRetries,
		waitMin:    1 * time.Second,
		waitMax:    30 * time.Second,
	}
}

func (rt *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := rt.maxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	var resp *http.Response
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// rewind the body for the retry, if possible
			if req.GetBody != nil {
				if body, berr := req.GetBody(); berr == nil {
					req.Body = body
				}
			}
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(rt.backoff(attempt)):
			}
		}

		resp, err = rt.next.RoundTrip(req)
		if !shouldRetry(resp, err) {
			return resp, err
		}
		// drain the failed response before retrying so the connection is reusable
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}
	return resp, err
}

func (rt *retryRoundTripper) backoff(attempt int) time.Duration {
	d := rt.waitMin << (attempt - 1)
	if d <= 0 || d > rt.waitMax {
		d = rt.waitMax
	}
	return d
}

// shouldRetry mirrors retryablehttp's default retry policy.
func shouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return true
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented {
		return true
	}
	return false
}
