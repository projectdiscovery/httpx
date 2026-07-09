package httpx

import (
	"net/http"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/networkpolicy"
)

// DefaultMaxResponseBodySize is the default maximum response body size that httpx
// reads into memory for processing (and, via the runner, the default cap for
// responses stored to disk with -sr). It is intentionally bounded: the body is
// held in memory and the footprint scales with the number of concurrent threads,
// so a very large cap can lead to excessive memory usage / OOM on large
// responses. Normal web pages are far smaller than this; use -rstr / -rsts to
// read or store larger responses when needed.
//
// NOTE: this is a var initializer (not an init() function) on purpose. init()
// functions run after all package-level variable initializers, so computing the
// value in init() left DefaultOptions (which references it below) observing a
// zero value during package initialization.
var DefaultMaxResponseBodySize = func() int64 {
	maxResponseBodySize, _ := humanize.ParseBytes("50mb")
	return int64(maxResponseBodySize)
}()

// Options contains configuration options for the client
type Options struct {
	RandomAgent      bool
	AutoReferer      bool
	DefaultUserAgent string
	Proxy            string
	// Deprecated: use Proxy
	HTTPProxy string
	// Deprecated: use Proxy
	SocksProxy  string
	Threads     int
	CdnCheck    string
	ExcludeCdn  bool
	ExtractFqdn bool
	// Timeout is the maximum time to wait for the request
	Timeout time.Duration
	// RetryMax is the maximum number of retries
	RetryMax      int
	CustomHeaders map[string][]string
	// VHostSimilarityRatio 1 - 100
	VHostSimilarityRatio int
	FollowRedirects      bool
	FollowHostRedirects  bool
	RespectHSTS          bool
	MaxRedirects         int
	Unsafe               bool
	TLSGrab              bool
	ZTLS                 bool
	// VHOSTs options
	VHostIgnoreStatusCode     bool
	VHostIgnoreContentLength  bool
	VHostIgnoreNumberOfWords  bool
	VHostIgnoreNumberOfLines  bool
	VHostStripHTML            bool
	MaxResponseBodySizeToSave int64
	MaxResponseBodySizeToRead int64
	UnsafeURI                 string
	Resolvers                 []string
	customCookies             []*http.Cookie
	SniName                   string
	TlsImpersonate            bool
	NetworkPolicy             *networkpolicy.NetworkPolicy
	CDNCheckClient            *cdncheck.Client
	Protocol                  Proto
	Trace                     bool
}

// DefaultOptions contains the default options
var DefaultOptions = Options{
	RandomAgent:               true,
	Threads:                   25,
	Timeout:                   30 * time.Second,
	RetryMax:                  5,
	MaxRedirects:              10,
	Unsafe:                    false,
	CdnCheck:                  "true",
	ExcludeCdn:                false,
	MaxResponseBodySizeToRead: DefaultMaxResponseBodySize,
	// VHOSTs options
	VHostIgnoreStatusCode:    false,
	VHostIgnoreContentLength: true,
	VHostIgnoreNumberOfWords: false,
	VHostIgnoreNumberOfLines: false,
	VHostStripHTML:           false,
	VHostSimilarityRatio:     85,
	DefaultUserAgent:         "httpx - Open-source project (github.com/projectdiscovery/httpx)",
}

func (options *Options) parseCustomCookies() {
	// parse and fill the custom field
	for k, v := range options.CustomHeaders {
		if strings.EqualFold(k, "cookie") {
			req := http.Request{Header: http.Header{"Cookie": v}}
			options.customCookies = req.Cookies()
		}
	}
}

func (options *Options) hasCustomCookies() bool {
	return len(options.customCookies) > 0
}
