package runner

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/common/customextract"
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/common/customlist"
	customport "github.com/projectdiscovery/httpx/common/customports"
	fileutilz "github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/stringz"
	"github.com/projectdiscovery/networkpolicy"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	updateutils "github.com/projectdiscovery/utils/update"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	two                    = 2
	defaultThreads         = 50
	DefaultResumeFile      = "resume.cfg"
	DefaultOutputDirectory = "output"
)

var (
	PDCPApiKey = ""
	TeamIDEnv  = env.GetEnvOrDefault("PDCP_TEAM_ID", "")
)

// OnResultCallback (hostResult)
type OnResultCallback func(Result)

type ScanOptions struct {
	Methods                   []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	StoreResponseDirectory    string   `json:"store_response_directory,omitempty" yaml:"store_response_directory,omitempty"`
	RequestURI                string   `json:"request_uri,omitempty" yaml:"request_uri,omitempty"`
	RequestBody               string   `json:"request_body,omitempty" yaml:"request_body,omitempty"`
	VHost                     bool     `json:"v_host,omitempty" yaml:"v_host,omitempty"`
	OutputTitle               bool     `json:"output_title,omitempty" yaml:"output_title,omitempty"`
	OutputStatusCode          bool     `json:"output_status_code,omitempty" yaml:"output_status_code,omitempty"`
	OutputLocation            bool     `json:"output_location,omitempty" yaml:"output_location,omitempty"`
	OutputContentLength       bool     `json:"output_content_length,omitempty" yaml:"output_content_length,omitempty"`
	StoreResponse             bool     `json:"store_response,omitempty" yaml:"store_response,omitempty"`
	OmitBody                  bool     `json:"omit_body,omitempty" yaml:"omit_body,omitempty"`
	OutputServerHeader        bool     `json:"output_server_header,omitempty" yaml:"output_server_header,omitempty"`
	OutputWebSocket           bool     `json:"output_web_socket,omitempty" yaml:"output_web_socket,omitempty"`
	OutputWithNoColor         bool     `json:"output_with_no_color,omitempty" yaml:"output_with_no_color,omitempty"`
	OutputMethod              bool     `json:"output_method,omitempty" yaml:"output_method,omitempty"`
	ResponseHeadersInStdout   bool     `json:"response_headers_in_stdout,omitempty" yaml:"response_headers_in_stdout,omitempty"`
	ResponseInStdout          bool     `json:"response_in_stdout,omitempty" yaml:"response_in_stdout,omitempty"`
	Base64ResponseInStdout    bool     `json:"base_64_response_in_stdout,omitempty" yaml:"base_64_response_in_stdout,omitempty"`
	ChainInStdout             bool     `json:"chain_in_stdout,omitempty" yaml:"chain_in_stdout,omitempty"`
	TLSProbe                  bool     `json:"tls_probe,omitempty" yaml:"tls_probe,omitempty"`
	CSPProbe                  bool     `json:"csp_probe,omitempty" yaml:"csp_probe,omitempty"`
	VHostInput                bool     `json:"v_host_input,omitempty" yaml:"v_host_input,omitempty"`
	OutputContentType         bool     `json:"output_content_type,omitempty" yaml:"output_content_type,omitempty"`
	Unsafe                    bool     `json:"unsafe,omitempty" yaml:"unsafe,omitempty"`
	Pipeline                  bool     `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	HTTP2Probe                bool     `json:"http_2_probe,omitempty" yaml:"http_2_probe,omitempty"`
	OutputIP                  bool     `json:"output_ip,omitempty" yaml:"output_ip,omitempty"`
	OutputCName               bool     `json:"output_c_name,omitempty" yaml:"output_c_name,omitempty"`
	OutputCDN                 string   `json:"output_cdn,omitempty" yaml:"output_cdn,omitempty"`
	OutputResponseTime        bool     `json:"output_response_time,omitempty" yaml:"output_response_time,omitempty"`
	PreferHTTPS               bool     `json:"prefer_https,omitempty" yaml:"prefer_https,omitempty"`
	NoFallback                bool     `json:"no_fallback,omitempty" yaml:"no_fallback,omitempty"`
	NoFallbackScheme          bool     `json:"no_fallback_scheme,omitempty" yaml:"no_fallback_scheme,omitempty"`
	TechDetect                bool     `json:"tech_detect,omitempty" yaml:"tech_detect,omitempty"`
	StoreChain                bool     `json:"store_chain,omitempty" yaml:"store_chain,omitempty"`
	StoreVisionReconClusters  bool     `json:"store_vision_recon_clusters,omitempty" yaml:"store_vision_recon_clusters,omitempty"`
	MaxResponseBodySizeToSave int      `json:"max_response_body_size_to_save,omitempty" yaml:"max_response_body_size_to_save,omitempty"`
	MaxResponseBodySizeToRead int      `json:"max_response_body_size_to_read,omitempty" yaml:"max_response_body_size_to_read,omitempty"`
	OutputExtractRegex        string   `json:"output_extract_regex,omitempty" yaml:"output_extract_regex,omitempty"`
	extractRegexps            map[string]*regexp.Regexp
	ExcludeCDN                bool          `json:"exclude_cdn,omitempty" yaml:"exclude_cdn,omitempty"`
	HostMaxErrors             int           `json:"host_max_errors,omitempty" yaml:"host_max_errors,omitempty"`
	ProbeAllIPS               bool          `json:"probe_all_ips,omitempty" yaml:"probe_all_ips,omitempty"`
	Favicon                   bool          `json:"favicon,omitempty" yaml:"favicon,omitempty"`
	LeaveDefaultPorts         bool          `json:"leave_default_ports,omitempty" yaml:"leave_default_ports,omitempty"`
	OutputLinesCount          bool          `json:"output_lines_count,omitempty" yaml:"output_lines_count,omitempty"`
	OutputWordsCount          bool          `json:"output_words_count,omitempty" yaml:"output_words_count,omitempty"`
	Hashes                    string        `json:"hashes,omitempty" yaml:"hashes,omitempty"`
	Screenshot                bool          `json:"screenshot,omitempty" yaml:"screenshot,omitempty"`
	UseInstalledChrome        bool          `json:"use_installed_chrome,omitempty" yaml:"use_installed_chrome,omitempty"`
	DisableStdin              bool          `json:"disable_stdin,omitempty" yaml:"disable_stdin,omitempty"`
	NoScreenshotBytes         bool          `json:"no_screenshot_bytes,omitempty" yaml:"no_screenshot_bytes,omitempty"`
	NoHeadlessBody            bool          `json:"no_headless_body,omitempty" yaml:"no_headless_body,omitempty"`
	NoScreenshotFullPage      bool          `json:"no_screenshot_full_page,omitempty" yaml:"no_screenshot_full_page,omitempty"`
	ScreenshotTimeout         time.Duration `json:"screenshot_timeout,omitempty" yaml:"screenshot_timeout,omitempty"`
	ScreenshotIdle            time.Duration `json:"screenshot_idle,omitempty" yaml:"screenshot_idle,omitempty"`
}

func (s *ScanOptions) IsScreenshotFullPage() bool {
	return !s.NoScreenshotFullPage
}

func (s *ScanOptions) Clone() *ScanOptions {
	return &ScanOptions{
		Methods:                   s.Methods,
		StoreResponseDirectory:    s.StoreResponseDirectory,
		RequestURI:                s.RequestURI,
		RequestBody:               s.RequestBody,
		VHost:                     s.VHost,
		OutputTitle:               s.OutputTitle,
		OutputStatusCode:          s.OutputStatusCode,
		OutputLocation:            s.OutputLocation,
		OutputContentLength:       s.OutputContentLength,
		StoreResponse:             s.StoreResponse,
		OmitBody:                  s.OmitBody,
		OutputServerHeader:        s.OutputServerHeader,
		OutputWebSocket:           s.OutputWebSocket,
		OutputWithNoColor:         s.OutputWithNoColor,
		OutputMethod:              s.OutputMethod,
		ResponseHeadersInStdout:   s.ResponseHeadersInStdout,
		ResponseInStdout:          s.ResponseInStdout,
		Base64ResponseInStdout:    s.Base64ResponseInStdout,
		ChainInStdout:             s.ChainInStdout,
		TLSProbe:                  s.TLSProbe,
		CSPProbe:                  s.CSPProbe,
		OutputContentType:         s.OutputContentType,
		Unsafe:                    s.Unsafe,
		Pipeline:                  s.Pipeline,
		HTTP2Probe:                s.HTTP2Probe,
		OutputIP:                  s.OutputIP,
		OutputCName:               s.OutputCName,
		OutputCDN:                 s.OutputCDN,
		OutputResponseTime:        s.OutputResponseTime,
		PreferHTTPS:               s.PreferHTTPS,
		NoFallback:                s.NoFallback,
		NoFallbackScheme:          s.NoFallbackScheme,
		TechDetect:                s.TechDetect,
		StoreChain:                s.StoreChain,
		OutputExtractRegex:        s.OutputExtractRegex,
		MaxResponseBodySizeToSave: s.MaxResponseBodySizeToSave,
		MaxResponseBodySizeToRead: s.MaxResponseBodySizeToRead,
		HostMaxErrors:             s.HostMaxErrors,
		Favicon:                   s.Favicon,
		extractRegexps:            s.extractRegexps,
		LeaveDefaultPorts:         s.LeaveDefaultPorts,
		OutputLinesCount:          s.OutputLinesCount,
		OutputWordsCount:          s.OutputWordsCount,
		Hashes:                    s.Hashes,
		Screenshot:                s.Screenshot,
		UseInstalledChrome:        s.UseInstalledChrome,
		NoScreenshotBytes:         s.NoScreenshotBytes,
		NoHeadlessBody:            s.NoHeadlessBody,
		NoScreenshotFullPage:      s.NoScreenshotFullPage,
		ScreenshotTimeout:         s.ScreenshotTimeout,
		ScreenshotIdle:            s.ScreenshotIdle,
	}
}

// Options contains configuration options for httpx.
type Options struct {
	CustomHeaders       customheader.CustomHeaders `json:"custom_headers,omitempty" yaml:"custom_headers,omitempty"`
	CustomPorts         customport.CustomPorts     `json:"custom_ports,omitempty" yaml:"custom_ports,omitempty"`
	matchStatusCode     []int
	matchContentLength  []int
	filterStatusCode    []int
	filterContentLength []int
	Output              string `json:"output,omitempty" yaml:"output,omitempty"`
	OutputAll           bool   `json:"output_all,omitempty" yaml:"output_all,omitempty"`
	StoreResponseDir    string `json:"store_response_dir,omitempty" yaml:"store_response_dir,omitempty"`
	OmitBody            bool   `json:"omit_body,omitempty" yaml:"omit_body,omitempty"`
	// Deprecated: use Proxy
	HTTPProxy string `json:"http_proxy,omitempty" yaml:"http_proxy,omitempty"`
	// Deprecated: use Proxy
	SocksProxy                string              `json:"socks_proxy,omitempty" yaml:"socks_proxy,omitempty"`
	Proxy                     string              `json:"proxy,omitempty" yaml:"proxy,omitempty"`
	InputFile                 string              `json:"input_file,omitempty" yaml:"input_file,omitempty"`
	InputTargetHost           goflags.StringSlice `json:"input_target_host,omitempty" yaml:"input_target_host,omitempty"`
	Methods                   string              `json:"methods,omitempty" yaml:"methods,omitempty"`
	RequestURI                string              `json:"request_uri,omitempty" yaml:"request_uri,omitempty"`
	RequestURIs               string              `json:"request_uris,omitempty" yaml:"request_uris,omitempty"`
	requestURIs               []string
	OutputMatchStatusCode     string `json:"output_match_status_code,omitempty" yaml:"output_match_status_code,omitempty"`
	OutputMatchContentLength  string `json:"output_match_content_length,omitempty" yaml:"output_match_content_length,omitempty"`
	OutputFilterStatusCode    string `json:"output_filter_status_code,omitempty" yaml:"output_filter_status_code,omitempty"`
	OutputFilterErrorPage     bool   `json:"output_filter_error_page,omitempty" yaml:"output_filter_error_page,omitempty"`
	FilterOutDuplicates       bool   `json:"filter_out_duplicates,omitempty" yaml:"filter_out_duplicates,omitempty"`
	OutputFilterContentLength string `json:"output_filter_content_length,omitempty" yaml:"output_filter_content_length,omitempty"`
	InputRawRequest           string `json:"input_raw_request,omitempty" yaml:"input_raw_request,omitempty"`
	rawRequest                string
	RequestBody               string              `json:"request_body,omitempty" yaml:"request_body,omitempty"`
	OutputFilterString        goflags.StringSlice `json:"output_filter_string,omitempty" yaml:"output_filter_string,omitempty"`
	OutputMatchString         goflags.StringSlice `json:"output_match_string,omitempty" yaml:"output_match_string,omitempty"`
	OutputFilterRegex         goflags.StringSlice `json:"output_filter_regex,omitempty" yaml:"output_filter_regex,omitempty"`
	OutputMatchRegex          goflags.StringSlice `json:"output_match_regex,omitempty" yaml:"output_match_regex,omitempty"`
	Retries                   int                 `json:"retries,omitempty" yaml:"retries,omitempty"`
	Threads                   int                 `json:"threads,omitempty" yaml:"threads,omitempty"`
	Timeout                   int                 `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Delay                     time.Duration       `json:"delay,omitempty" yaml:"delay,omitempty"`
	filterRegexes             []*regexp.Regexp
	matchRegexes              []*regexp.Regexp
	VHost                     bool   `json:"v_host,omitempty" yaml:"v_host,omitempty"`
	VHostInput                bool   `json:"v_host_input,omitempty" yaml:"v_host_input,omitempty"`
	Smuggling                 bool   `json:"smuggling,omitempty" yaml:"smuggling,omitempty"`
	ExtractTitle              bool   `json:"extract_title,omitempty" yaml:"extract_title,omitempty"`
	StatusCode                bool   `json:"status_code,omitempty" yaml:"status_code,omitempty"`
	Location                  bool   `json:"location,omitempty" yaml:"location,omitempty"`
	ContentLength             bool   `json:"content_length,omitempty" yaml:"content_length,omitempty"`
	FollowRedirects           bool   `json:"follow_redirects,omitempty" yaml:"follow_redirects,omitempty"`
	RespectHSTS               bool   `json:"respect_hsts,omitempty" yaml:"respect_hsts,omitempty"`
	StoreResponse             bool   `json:"store_response,omitempty" yaml:"store_response,omitempty"`
	JSONOutput                bool   `json:"json_output,omitempty" yaml:"json_output,omitempty"`
	CSVOutput                 bool   `json:"csv_output,omitempty" yaml:"csv_output,omitempty"`
	CSVOutputEncoding         string `json:"csv_output_encoding,omitempty" yaml:"csv_output_encoding,omitempty"`
	PdcpAuth                  string `json:"pdcp_auth,omitempty" yaml:"pdcp_auth,omitempty"`
	PdcpAuthCredFile          string `json:"pdcp_auth_cred_file,omitempty" yaml:"pdcp_auth_cred_file,omitempty"`
	Silent                    bool   `json:"silent,omitempty" yaml:"silent,omitempty"`
	Version                   bool   `json:"version,omitempty" yaml:"version,omitempty"`
	Verbose                   bool   `json:"verbose,omitempty" yaml:"verbose,omitempty"`
	NoColor                   bool   `json:"no_color,omitempty" yaml:"no_color,omitempty"`
	OutputServerHeader        bool   `json:"output_server_header,omitempty" yaml:"output_server_header,omitempty"`
	OutputWebSocket           bool   `json:"output_web_socket,omitempty" yaml:"output_web_socket,omitempty"`
	ResponseHeadersInStdout   bool   `json:"response_headers_in_stdout,omitempty" yaml:"response_headers_in_stdout,omitempty"`
	ResponseInStdout          bool   `json:"response_in_stdout,omitempty" yaml:"response_in_stdout,omitempty"`
	Base64ResponseInStdout    bool   `json:"base_64_response_in_stdout,omitempty" yaml:"base_64_response_in_stdout,omitempty"`
	ChainInStdout             bool   `json:"chain_in_stdout,omitempty" yaml:"chain_in_stdout,omitempty"`
	FollowHostRedirects       bool   `json:"follow_host_redirects,omitempty" yaml:"follow_host_redirects,omitempty"`
	MaxRedirects              int    `json:"max_redirects,omitempty" yaml:"max_redirects,omitempty"`
	OutputMethod              bool   `json:"output_method,omitempty" yaml:"output_method,omitempty"`
	TLSProbe                  bool   `json:"tls_probe,omitempty" yaml:"tls_probe,omitempty"`
	CSPProbe                  bool   `json:"csp_probe,omitempty" yaml:"csp_probe,omitempty"`
	OutputContentType         bool   `json:"output_content_type,omitempty" yaml:"output_content_type,omitempty"`
	OutputIP                  bool   `json:"output_ip,omitempty" yaml:"output_ip,omitempty"`
	OutputCName               bool   `json:"output_c_name,omitempty" yaml:"output_c_name,omitempty"`
	ExtractFqdn               bool   `json:"extract_fqdn,omitempty" yaml:"extract_fqdn,omitempty"`
	Unsafe                    bool   `json:"unsafe,omitempty" yaml:"unsafe,omitempty"`
	Debug                     bool   `json:"debug,omitempty" yaml:"debug,omitempty"`
	DebugRequests             bool   `json:"debug_requests,omitempty" yaml:"debug_requests,omitempty"`
	DebugResponse             bool   `json:"debug_response,omitempty" yaml:"debug_response,omitempty"`
	Pipeline                  bool   `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	HTTP2Probe                bool   `json:"http_2_probe,omitempty" yaml:"http_2_probe,omitempty"`
	OutputCDN                 string `json:"output_cdn,omitempty" yaml:"output_cdn,omitempty"`
	OutputResponseTime        bool   `json:"output_response_time,omitempty" yaml:"output_response_time,omitempty"`
	NoFallback                bool   `json:"no_fallback,omitempty" yaml:"no_fallback,omitempty"`
	NoFallbackScheme          bool   `json:"no_fallback_scheme,omitempty" yaml:"no_fallback_scheme,omitempty"`
	TechDetect                bool   `json:"tech_detect,omitempty" yaml:"tech_detect,omitempty"`
	TLSGrab                   bool   `json:"tls_grab,omitempty" yaml:"tls_grab,omitempty"`
	protocol                  string
	ShowStatistics            bool                  `json:"show_statistics,omitempty" yaml:"show_statistics,omitempty"`
	StatsInterval             int                   `json:"stats_interval,omitempty" yaml:"stats_interval,omitempty"`
	RandomAgent               bool                  `json:"random_agent,omitempty" yaml:"random_agent,omitempty"`
	StoreChain                bool                  `json:"store_chain,omitempty" yaml:"store_chain,omitempty"`
	StoreVisionReconClusters  bool                  `json:"store_vision_recon_clusters,omitempty" yaml:"store_vision_recon_clusters,omitempty"`
	Deny                      customlist.CustomList `json:"deny,omitempty" yaml:"deny,omitempty"`
	Allow                     customlist.CustomList `json:"allow,omitempty" yaml:"allow,omitempty"`
	MaxResponseBodySizeToSave int                   `json:"max_response_body_size_to_save,omitempty" yaml:"max_response_body_size_to_save,omitempty"`
	MaxResponseBodySizeToRead int                   `json:"max_response_body_size_to_read,omitempty" yaml:"max_response_body_size_to_read,omitempty"`
	ResponseBodyPreviewSize   int                   `json:"response_body_preview_size,omitempty" yaml:"response_body_preview_size,omitempty"`
	OutputExtractRegexs       goflags.StringSlice   `json:"output_extract_regexs,omitempty" yaml:"output_extract_regexs,omitempty"`
	OutputExtractPresets      goflags.StringSlice   `json:"output_extract_presets,omitempty" yaml:"output_extract_presets,omitempty"`
	RateLimit                 int                   `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	RateLimitMinute           int                   `json:"rate_limit_minute,omitempty" yaml:"rate_limit_minute,omitempty"`
	Probe                     bool                  `json:"probe,omitempty" yaml:"probe,omitempty"`
	Resume                    bool                  `json:"resume,omitempty" yaml:"resume,omitempty"`
	resumeCfg                 *ResumeCfg
	Exclude                   goflags.StringSlice `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	HostMaxErrors             int                 `json:"host_max_errors,omitempty" yaml:"host_max_errors,omitempty"`
	Stream                    bool                `json:"stream,omitempty" yaml:"stream,omitempty"`
	SkipDedupe                bool                `json:"skip_dedupe,omitempty" yaml:"skip_dedupe,omitempty"`
	ProbeAllIPS               bool                `json:"probe_all_ips,omitempty" yaml:"probe_all_ips,omitempty"`
	Resolvers                 goflags.StringSlice `json:"resolvers,omitempty" yaml:"resolvers,omitempty"`
	Favicon                   bool                `json:"favicon,omitempty" yaml:"favicon,omitempty"`
	OutputFilterFavicon       goflags.StringSlice `json:"output_filter_favicon,omitempty" yaml:"output_filter_favicon,omitempty"`
	OutputMatchFavicon        goflags.StringSlice `json:"output_match_favicon,omitempty" yaml:"output_match_favicon,omitempty"`
	LeaveDefaultPorts         bool                `json:"leave_default_ports,omitempty" yaml:"leave_default_ports,omitempty"`
	ZTLS                      bool                `json:"ztls,omitempty" yaml:"ztls,omitempty"`
	OutputLinesCount          bool                `json:"output_lines_count,omitempty" yaml:"output_lines_count,omitempty"`
	OutputMatchLinesCount     string              `json:"output_match_lines_count,omitempty" yaml:"output_match_lines_count,omitempty"`
	matchLinesCount           []int
	OutputFilterLinesCount    string `json:"output_filter_lines_count,omitempty" yaml:"output_filter_lines_count,omitempty"`
	Memprofile                string `json:"memprofile,omitempty" yaml:"memprofile,omitempty"`
	filterLinesCount          []int
	OutputWordsCount          bool   `json:"output_words_count,omitempty" yaml:"output_words_count,omitempty"`
	OutputMatchWordsCount     string `json:"output_match_words_count,omitempty" yaml:"output_match_words_count,omitempty"`
	matchWordsCount           []int
	OutputFilterWordsCount    string `json:"output_filter_words_count,omitempty" yaml:"output_filter_words_count,omitempty"`
	filterWordsCount          []int
	Hashes                    string              `json:"hashes,omitempty" yaml:"hashes,omitempty"`
	Jarm                      bool                `json:"jarm,omitempty" yaml:"jarm,omitempty"`
	Asn                       bool                `json:"asn,omitempty" yaml:"asn,omitempty"`
	OutputMatchCdn            goflags.StringSlice `json:"output_match_cdn,omitempty" yaml:"output_match_cdn,omitempty"`
	OutputFilterCdn           goflags.StringSlice `json:"output_filter_cdn,omitempty" yaml:"output_filter_cdn,omitempty"`
	SniName                   string              `json:"sni_name,omitempty" yaml:"sni_name,omitempty"`
	OutputMatchResponseTime   string              `json:"output_match_response_time,omitempty" yaml:"output_match_response_time,omitempty"`
	OutputFilterResponseTime  string              `json:"output_filter_response_time,omitempty" yaml:"output_filter_response_time,omitempty"`
	HealthCheck               bool                `json:"health_check,omitempty" yaml:"health_check,omitempty"`
	ListDSLVariable           bool                `json:"list_dsl_variable,omitempty" yaml:"list_dsl_variable,omitempty"`
	OutputFilterCondition     string              `json:"output_filter_condition,omitempty" yaml:"output_filter_condition,omitempty"`
	OutputMatchCondition      string              `json:"output_match_condition,omitempty" yaml:"output_match_condition,omitempty"`
	StripFilter               string              `json:"strip_filter,omitempty" yaml:"strip_filter,omitempty"`
	//The OnResult callback function is invoked for each result. It is important to check for errors in the result before using Result.Err.
	OnResult             OnResultCallback `json:"on_result,omitempty" yaml:"on_result,omitempty"`
	DisableUpdateCheck   bool             `json:"disable_update_check,omitempty" yaml:"disable_update_check,omitempty"`
	NoDecode             bool             `json:"no_decode,omitempty" yaml:"no_decode,omitempty"`
	Screenshot           bool             `json:"screenshot,omitempty" yaml:"screenshot,omitempty"`
	UseInstalledChrome   bool             `json:"use_installed_chrome,omitempty" yaml:"use_installed_chrome,omitempty"`
	TlsImpersonate       bool             `json:"tls_impersonate,omitempty" yaml:"tls_impersonate,omitempty"`
	DisableStdin         bool             `json:"disable_stdin,omitempty" yaml:"disable_stdin,omitempty"`
	HttpApiEndpoint      string           `json:"http_api_endpoint,omitempty" yaml:"http_api_endpoint,omitempty"`
	NoScreenshotBytes    bool             `json:"no_screenshot_bytes,omitempty" yaml:"no_screenshot_bytes,omitempty"`
	NoHeadlessBody       bool             `json:"no_headless_body,omitempty" yaml:"no_headless_body,omitempty"`
	NoScreenshotFullPage bool             `json:"no_screenshot_full_page,omitempty" yaml:"no_screenshot_full_page,omitempty"`
	ScreenshotTimeout    time.Duration    `json:"screenshot_timeout,omitempty" yaml:"screenshot_timeout,omitempty"`
	ScreenshotIdle       time.Duration    `json:"screenshot_idle,omitempty" yaml:"screenshot_idle,omitempty"`
	// HeadlessOptionalArguments specifies optional arguments to pass to Chrome
	HeadlessOptionalArguments goflags.StringSlice `json:"headless_optional_arguments,omitempty" yaml:"headless_optional_arguments,omitempty"`
	Protocol                  string              `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	OutputFilterErrorPagePath string              `json:"output_filter_error_page_path,omitempty" yaml:"output_filter_error_page_path,omitempty"`
	DisableStdout             bool                `json:"disable_stdout,omitempty" yaml:"disable_stdout,omitempty"`
	// AssetUpload
	AssetUpload bool `json:"asset_upload,omitempty" yaml:"asset_upload,omitempty"`
	// AssetName
	AssetName string `json:"asset_name,omitempty" yaml:"asset_name,omitempty"`
	// AssetID
	AssetID string `json:"asset_id,omitempty" yaml:"asset_id,omitempty"`
	// AssetFileUpload
	AssetFileUpload string `json:"asset_file_upload,omitempty" yaml:"asset_file_upload,omitempty"`
	TeamID          string `json:"team_id,omitempty" yaml:"team_id,omitempty"`
	// OnClose adds a callback function that is invoked when httpx is closed
	// to be exact at end of existing closures
	OnClose func() `json:"-" yaml:"-"`

	Trace bool `json:"trace,omitempty" yaml:"trace,omitempty"`

	// Optional pre-created objects to reduce allocations
	Wappalyzer     *wappalyzer.Wappalyze        `json:"wappalyzer,omitempty" yaml:"wappalyzer,omitempty"`
	Networkpolicy  *networkpolicy.NetworkPolicy `json:"networkpolicy,omitempty" yaml:"networkpolicy,omitempty"`
	CDNCheckClient *cdncheck.Client             `json:"cdn_check_client,omitempty" yaml:"cdn_check_client,omitempty"`
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	var cfgFile string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "input file containing list of hosts to process"),
		flagSet.StringVarP(&options.InputRawRequest, "request", "rr", "", "file containing raw request"),
		flagSet.StringSliceVarP(&options.InputTargetHost, "target", "u", nil, "input target host(s) to probe", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("Probes", "Probes",
		flagSet.BoolVarP(&options.StatusCode, "status-code", "sc", false, "display response status-code"),
		flagSet.BoolVarP(&options.ContentLength, "content-length", "cl", false, "display response content-length"),
		flagSet.BoolVarP(&options.OutputContentType, "content-type", "ct", false, "display response content-type"),
		flagSet.BoolVar(&options.Location, "location", false, "display response redirect location"),
		flagSet.BoolVar(&options.Favicon, "favicon", false, "display mmh3 hash for '/favicon.ico' file"),
		flagSet.StringVar(&options.Hashes, "hash", "", "display response body hash (supported: md5,mmh3,simhash,sha1,sha256,sha512)"),
		flagSet.BoolVar(&options.Jarm, "jarm", false, "display jarm fingerprint hash"),
		flagSet.BoolVarP(&options.OutputResponseTime, "response-time", "rt", false, "display response time"),
		flagSet.BoolVarP(&options.OutputLinesCount, "line-count", "lc", false, "display response body line count"),
		flagSet.BoolVarP(&options.OutputWordsCount, "word-count", "wc", false, "display response body word count"),
		flagSet.BoolVar(&options.ExtractTitle, "title", false, "display page title"),
		flagSet.DynamicVarP(&options.ResponseBodyPreviewSize, "body-preview", "bp", 100, "display first N characters of response body"),
		flagSet.BoolVarP(&options.OutputServerHeader, "web-server", "server", false, "display server name"),
		flagSet.BoolVarP(&options.TechDetect, "tech-detect", "td", false, "display technology in use based on wappalyzer dataset"),
		flagSet.BoolVar(&options.OutputMethod, "method", false, "display http request method"),
		flagSet.BoolVar(&options.OutputWebSocket, "websocket", false, "display server using websocket"),
		flagSet.BoolVar(&options.OutputIP, "ip", false, "display host ip"),
		flagSet.BoolVar(&options.OutputCName, "cname", false, "display host cname"),
		flagSet.BoolVarP(&options.ExtractFqdn, "efqdn", "extract-fqdn", false, "get domain and subdomains from response body and header in jsonl/csv output"),
		flagSet.BoolVar(&options.Asn, "asn", false, "display host asn information"),
		flagSet.DynamicVar(&options.OutputCDN, "cdn", "true", "display cdn/waf in use"),
		flagSet.BoolVar(&options.Probe, "probe", false, "display probe status"),
	)

	flagSet.CreateGroup("headless", "Headless",
		flagSet.BoolVarP(&options.Screenshot, "screenshot", "ss", false, "enable saving screenshot of the page using headless browser"),
		flagSet.BoolVar(&options.UseInstalledChrome, "system-chrome", false, "enable using local installed chrome for screenshot"),
		flagSet.StringSliceVarP(&options.HeadlessOptionalArguments, "headless-options", "ho", nil, "start headless chrome with additional options", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.NoScreenshotBytes, "exclude-screenshot-bytes", "esb", false, "enable excluding screenshot bytes from json output"),
		flagSet.BoolVarP(&options.NoHeadlessBody, "exclude-headless-body", "ehb", false, "enable excluding headless header from json output"),
		flagSet.BoolVar(&options.NoScreenshotFullPage, "no-screenshot-full-page", false, "disable saving full page screenshot"),
		flagSet.DurationVarP(&options.ScreenshotTimeout, "screenshot-timeout", "st", 10*time.Second, "set timeout for screenshot in seconds"),
		flagSet.DurationVarP(&options.ScreenshotIdle, "screenshot-idle", "sid", 1*time.Second, "set idle time before taking screenshot in seconds"),
	)

	flagSet.CreateGroup("matchers", "Matchers",
		flagSet.StringVarP(&options.OutputMatchStatusCode, "match-code", "mc", "", "match response with specified status code (-mc 200,302)"),
		flagSet.StringVarP(&options.OutputMatchContentLength, "match-length", "ml", "", "match response with specified content length (-ml 100,102)"),
		flagSet.StringVarP(&options.OutputMatchLinesCount, "match-line-count", "mlc", "", "match response body with specified line count (-mlc 423,532)"),
		flagSet.StringVarP(&options.OutputMatchWordsCount, "match-word-count", "mwc", "", "match response body with specified word count (-mwc 43,55)"),
		flagSet.StringSliceVarP(&options.OutputMatchFavicon, "match-favicon", "mfc", nil, "match response with specified favicon hash (-mfc 1494302000)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputMatchString, "match-string", "ms", nil, "match response with specified string (-ms admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputMatchRegex, "match-regex", "mr", nil, "match response with specified regex (-mr admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputMatchCdn, "match-cdn", "mcdn", nil, fmt.Sprintf("match host with specified cdn provider (%s)", cdncheck.DefaultCDNProviders), goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.OutputMatchResponseTime, "match-response-time", "mrt", "", "match response with specified response time in seconds (-mrt '< 1')"),
		flagSet.StringVarP(&options.OutputMatchCondition, "match-condition", "mdc", "", "match response with dsl expression condition"),
	)

	flagSet.CreateGroup("extractor", "Extractor",
		flagSet.StringSliceVarP(&options.OutputExtractRegexs, "extract-regex", "er", nil, "display response content with matched regex", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputExtractPresets, "extract-preset", "ep", nil, fmt.Sprintf("display response content matched by a pre-defined regex (%s)", strings.Join(maps.Keys(customextract.ExtractPresets), ",")), goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("filters", "Filters",
		flagSet.StringVarP(&options.OutputFilterStatusCode, "filter-code", "fc", "", "filter response with specified status code (-fc 403,401)"),
		flagSet.BoolVarP(&options.OutputFilterErrorPage, "filter-error-page", "fep", false, "filter response with ML based error page detection"),
		flagSet.BoolVarP(&options.FilterOutDuplicates, "filter-duplicates", "fd", false, "filter out near-duplicate responses (only first response is retained)"),
		flagSet.StringVarP(&options.OutputFilterContentLength, "filter-length", "fl", "", "filter response with specified content length (-fl 23,33)"),
		flagSet.StringVarP(&options.OutputFilterLinesCount, "filter-line-count", "flc", "", "filter response body with specified line count (-flc 423,532)"),
		flagSet.StringVarP(&options.OutputFilterWordsCount, "filter-word-count", "fwc", "", "filter response body with specified word count (-fwc 423,532)"),
		flagSet.StringSliceVarP(&options.OutputFilterFavicon, "filter-favicon", "ffc", nil, "filter response with specified favicon hash (-ffc 1494302000)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputFilterString, "filter-string", "fs", nil, "filter response with specified string (-fs admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputFilterRegex, "filter-regex", "fe", nil, "filter response with specified regex (-fe admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputFilterCdn, "filter-cdn", "fcdn", nil, fmt.Sprintf("filter host with specified cdn provider (%s)", cdncheck.DefaultCDNProviders), goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.OutputFilterResponseTime, "filter-response-time", "frt", "", "filter response with specified response time in seconds (-frt '> 1')"),
		flagSet.StringVarP(&options.OutputFilterCondition, "filter-condition", "fdc", "", "filter response with dsl expression condition"),
		flagSet.DynamicVar(&options.StripFilter, "strip", "html", "strips all tags in response. supported formats: html,xml"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVarP(&options.Threads, "threads", "t", defaultThreads, "number of threads to use"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "maximum requests to send per second"),
		flagSet.IntVarP(&options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "maximum number of requests to send per minute"),
	)

	flagSet.CreateGroup("Misc", "Miscellaneous",
		flagSet.BoolVarP(&options.ProbeAllIPS, "probe-all-ips", "pa", false, "probe all the ips associated with same host"),
		flagSet.VarP(&options.CustomPorts, "ports", "p", "ports to probe (nmap syntax: eg http:1,2-10,11,https:80)"),
		flagSet.StringVar(&options.RequestURIs, "path", "", "path or list of paths to probe (comma-separated, file)"),
		flagSet.BoolVar(&options.TLSProbe, "tls-probe", false, "send http probes on the extracted TLS domains (dns_name)"),
		flagSet.BoolVar(&options.CSPProbe, "csp-probe", false, "send http probes on the extracted CSP domains"),
		flagSet.BoolVar(&options.TLSGrab, "tls-grab", false, "perform TLS(SSL) data grabbing"),
		flagSet.BoolVar(&options.Pipeline, "pipeline", false, "probe and display server supporting HTTP1.1 pipeline"),
		flagSet.BoolVar(&options.HTTP2Probe, "http2", false, "probe and display server supporting HTTP2"),
		flagSet.BoolVar(&options.VHost, "vhost", false, "probe and display server supporting VHOST"),
		flagSet.BoolVarP(&options.ListDSLVariable, "list-dsl-variables", "ldv", false, "list json output field keys name that support dsl matcher/filter"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update httpx to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic httpx update check"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output results"),
		flagSet.BoolVarP(&options.OutputAll, "output-all", "oa", false, "filename to write output results in all formats"),
		flagSet.BoolVarP(&options.StoreResponse, "store-response", "sr", false, "store http response to output directory"),
		flagSet.StringVarP(&options.StoreResponseDir, "store-response-dir", "srd", "", "store http response to custom directory"),
		flagSet.BoolVarP(&options.OmitBody, "omit-body", "ob", false, "omit response body in output"),
		flagSet.BoolVar(&options.CSVOutput, "csv", false, "store output in csv format"),
		flagSet.StringVarP(&options.CSVOutputEncoding, "csv-output-encoding", "csvo", "", "define output encoding"),
		flagSet.BoolVarP(&options.JSONOutput, "json", "j", false, "store output in JSONL(ines) format"),
		flagSet.BoolVarP(&options.ResponseHeadersInStdout, "include-response-header", "irh", false, "include http response (headers) in JSON output (-json only)"),
		flagSet.BoolVarP(&options.ResponseInStdout, "include-response", "irr", false, "include http request/response (headers + body) in JSON output (-json only)"),
		flagSet.BoolVarP(&options.Base64ResponseInStdout, "include-response-base64", "irrb", false, "include base64 encoded http request/response in JSON output (-json only)"),
		flagSet.BoolVar(&options.ChainInStdout, "include-chain", false, "include redirect http chain in JSON output (-json only)"),
		flagSet.BoolVar(&options.StoreChain, "store-chain", false, "include http redirect chain in responses (-sr only)"),
		flagSet.BoolVarP(&options.StoreVisionReconClusters, "store-vision-recon-cluster", "svrc", false, "include visual recon clusters (-ss and -sr only)"),
		flagSet.StringVarP(&options.Protocol, "protocol", "pr", "", "protocol to use (unknown, http11)"),
		flagSet.StringVarP(&options.OutputFilterErrorPagePath, "filter-error-page-path", "fepp", "filtered_error_page.json", "path to store filtered error pages"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the httpx configuration file (default $HOME/.config/httpx/config.yaml)"),
		flagSet.StringSliceVarP(&options.Resolvers, "resolvers", "r", nil, "list of custom resolver (file or comma separated)", goflags.NormalizedStringSliceOptions),
		flagSet.Var(&options.Allow, "allow", "allowed list of IP/CIDR's to process (file or comma separated)"),
		flagSet.Var(&options.Deny, "deny", "denied list of IP/CIDR's to process (file or comma separated)"),
		flagSet.StringVarP(&options.SniName, "sni-name", "sni", "", "custom TLS SNI name"),
		flagSet.BoolVar(&options.RandomAgent, "random-agent", true, "enable Random User-Agent to use"),
		flagSet.VarP(&options.CustomHeaders, "header", "H", "custom http headers to send with request"),
		flagSet.StringVarP(&options.Proxy, "proxy", "http-proxy", "", "proxy (http|socks) to use (eg http://127.0.0.1:8080)"),
		flagSet.BoolVar(&options.Unsafe, "unsafe", false, "send raw requests skipping golang normalization"),
		flagSet.BoolVar(&options.Resume, "resume", false, "resume scan using resume.cfg"),
		flagSet.BoolVarP(&options.FollowRedirects, "follow-redirects", "fr", false, "follow http redirects"),
		flagSet.IntVarP(&options.MaxRedirects, "max-redirects", "maxr", 10, "max number of redirects to follow per host"),
		flagSet.BoolVarP(&options.FollowHostRedirects, "follow-host-redirects", "fhr", false, "follow redirects on the same host"),
		flagSet.BoolVarP(&options.RespectHSTS, "respect-hsts", "rhsts", false, "respect HSTS response headers for redirect requests"),
		flagSet.BoolVar(&options.VHostInput, "vhost-input", false, "get a list of vhosts as input"),
		flagSet.StringVar(&options.Methods, "x", "", "request methods to probe, use 'all' to probe all HTTP methods"),
		flagSet.StringVar(&options.RequestBody, "body", "", "post body to include in http request"),
		flagSet.BoolVarP(&options.Stream, "stream", "s", false, "stream mode - start elaborating input targets without sorting"),
		flagSet.BoolVarP(&options.SkipDedupe, "skip-dedupe", "sd", false, "disable dedupe input items (only used with stream mode)"),
		flagSet.BoolVarP(&options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "leave default http/https ports in host header (eg. http://host:80 - https://host:443"),
		flagSet.BoolVar(&options.ZTLS, "ztls", false, "use ztls library with autofallback to standard one for tls13"),
		flagSet.BoolVar(&options.NoDecode, "no-decode", false, "avoid decoding body"),
		flagSet.BoolVarP(&options.TlsImpersonate, "tls-impersonate", "tlsi", false, "enable experimental client hello (ja3) tls randomization"),
		flagSet.BoolVar(&options.DisableStdin, "no-stdin", false, "Disable Stdin processing"),
		flagSet.StringVarP(&options.HttpApiEndpoint, "http-api-endpoint", "hae", "", "experimental http api endpoint"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&options.HealthCheck, "hc", "health-check", false, "run diagnostic check up"),
		flagSet.BoolVar(&options.Debug, "debug", false, "display request/response content in cli"),
		flagSet.BoolVar(&options.DebugRequests, "debug-req", false, "display request content in cli"),
		flagSet.BoolVar(&options.DebugResponse, "debug-resp", false, "display response content in cli"),
		flagSet.BoolVar(&options.Version, "version", false, "display httpx version"),
		flagSet.BoolVar(&options.ShowStatistics, "stats", false, "display scan statistic"),
		flagSet.StringVar(&options.Memprofile, "profile-mem", "", "optional httpx memory profile dump file"),
		flagSet.BoolVar(&options.Silent, "silent", false, "silent mode"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "verbose mode"),
		flagSet.IntVarP(&options.StatsInterval, "stats-interval", "si", 0, "number of seconds to wait between showing a statistics update (default: 5)"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colors in cli output"),
		flagSet.BoolVarP(&options.Trace, "trace", "tr", false, "trace"),
	)

	flagSet.CreateGroup("Optimizations", "Optimizations",
		flagSet.BoolVarP(&options.NoFallback, "no-fallback", "nf", false, "display both probed protocol (HTTPS and HTTP)"),
		flagSet.BoolVarP(&options.NoFallbackScheme, "no-fallback-scheme", "nfs", false, "probe with protocol scheme specified in input "),
		flagSet.IntVarP(&options.HostMaxErrors, "max-host-error", "maxhr", 30, "max error count per host before skipping remaining path/s"),
		flagSet.StringSliceVarP(&options.Exclude, "exclude", "e", nil, "exclude host matching specified filter ('cdn', 'private-ips', cidr, ip, regex)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.IntVar(&options.Retries, "retries", 0, "number of retries"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "timeout in seconds"),
		flagSet.DurationVar(&options.Delay, "delay", -1, "duration between each http request (eg: 200ms, 1s)"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToSave, "response-size-to-save", "rsts", math.MaxInt32, "max response size to save in bytes"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToRead, "response-size-to-read", "rstr", math.MaxInt32, "max response size to read in bytes"),
	)

	flagSet.CreateGroup("cloud", "Cloud",
		flagSet.DynamicVar(&options.PdcpAuth, "auth", "true", "configure projectdiscovery cloud (pdcp) api key"),
		flagSet.StringVarP(&options.PdcpAuthCredFile, "auth-config", "ac", "", "configure projectdiscovery cloud (pdcp) api key credential file"),
		flagSet.BoolVarP(&options.AssetUpload, "dashboard", "pd", false, "upload / view output in projectdiscovery cloud (pdcp) UI dashboard"),
		flagSet.StringVarP(&options.TeamID, "team-id", "tid", TeamIDEnv, "upload asset results to given team id (optional)"),
		flagSet.StringVarP(&options.AssetID, "asset-id", "aid", "", "upload new assets to existing asset id (optional)"),
		flagSet.StringVarP(&options.AssetName, "asset-name", "aname", "", "assets group name to set (optional)"),
		flagSet.StringVarP(&options.AssetFileUpload, "dashboard-upload", "pdu", "", "upload httpx output file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard"),
	)

	_ = flagSet.Parse()

	if options.OutputAll && options.Output == "" {
		gologger.Fatal().Msg("Please specify an output file using -o/-output when using -oa/-output-all")
	}

	if options.OutputAll {
		options.JSONOutput = true
		options.CSVOutput = true
	}

	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	if options.PdcpAuthCredFile != "" {
		pdcpauth.PDCPCredFile = options.PdcpAuthCredFile
		pdcpauth.PDCPDir = filepath.Dir(pdcpauth.PDCPCredFile)
	}

	// api key hierarchy: cli flag > env var > .pdcp/credential file
	if options.PdcpAuth == "true" {
		AuthWithPDCP()
	} else if len(options.PdcpAuth) == 36 {
		PDCPApiKey = options.PdcpAuth
		ph := pdcpauth.PDCPCredHandler{}
		if _, err := ph.GetCreds(); err == pdcpauth.ErrNoCreds {
			apiServer := env.GetEnvOrDefault("PDCP_API_SERVER", pdcpauth.DefaultApiServer)
			if validatedCreds, err := ph.ValidateAPIKey(PDCPApiKey, apiServer, "httpx"); err == nil {
				_ = ph.SaveCreds(validatedCreds)
			}
		}
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", DoHealthCheck(options, flagSet))
		os.Exit(0)
	}

	if options.StatsInterval != 0 {
		options.ShowStatistics = true
	}

	if options.ResponseBodyPreviewSize > 0 && options.StripFilter == "" {
		options.StripFilter = "html"
	}

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}
	if options.ListDSLVariable {
		dslVars, err := dslVariables()
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		for _, dsl := range dslVars {
			gologger.Print().Msg(dsl)
		}
		os.Exit(0)
	}
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("httpx", Version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("httpx version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current httpx version %v %v", Version, updateutils.GetVersionDescription(Version, latestVersion))
		}
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	return options
}

func (options *Options) ValidateOptions() error {
	if options.InputFile != "" && !fileutilz.FileNameIsGlob(options.InputFile) && !fileutil.FileExists(options.InputFile) {
		return fmt.Errorf("file '%s' does not exist", options.InputFile)
	}

	if options.InputRawRequest != "" && !fileutil.FileExists(options.InputRawRequest) {
		return fmt.Errorf("file '%s' does not exist", options.InputRawRequest)
	}

	if options.Silent {
		incompatibleFlagsList := flagsIncompatibleWithSilent(options)
		if len(incompatibleFlagsList) > 0 {
			last := incompatibleFlagsList[len(incompatibleFlagsList)-1]
			first := incompatibleFlagsList[:len(incompatibleFlagsList)-1]
			msg := ""
			if len(incompatibleFlagsList) > 1 {
				msg += fmt.Sprintf("%s and %s flags are", strings.Join(first, ", "), last)
			} else {
				msg += fmt.Sprintf("%s flag is", last)
			}
			msg += " incompatible with silent flag"
			return errors.New(msg)
		}
	}

	var err error
	if options.matchStatusCode, err = stringz.StringToSliceInt(options.OutputMatchStatusCode); err != nil {
		return errors.Wrap(err, "Invalid value for match status code option")
	}
	if options.matchContentLength, err = stringz.StringToSliceInt(options.OutputMatchContentLength); err != nil {
		return errors.Wrap(err, "Invalid value for match content length option")
	}
	if options.filterStatusCode, err = stringz.StringToSliceInt(options.OutputFilterStatusCode); err != nil {
		return errors.Wrap(err, "Invalid value for filter status code option")
	}
	if options.filterContentLength, err = stringz.StringToSliceInt(options.OutputFilterContentLength); err != nil {
		return errors.Wrap(err, "Invalid value for filter content length option")
	}
	for _, filterRegexStr := range options.OutputFilterRegex {
		filterRegex, err := regexp.Compile(filterRegexStr)
		if err != nil {
			return errors.Wrap(err, "Invalid value for regex filter option")
		}
		options.filterRegexes = append(options.filterRegexes, filterRegex)
	}

	for _, matchRegexStr := range options.OutputMatchRegex {
		matchRegex, err := regexp.Compile(matchRegexStr)
		if err != nil {
			return errors.Wrap(err, "Invalid value for match regex option")
		}
		options.matchRegexes = append(options.matchRegexes, matchRegex)
	}

	if options.matchLinesCount, err = stringz.StringToSliceInt(options.OutputMatchLinesCount); err != nil {
		return errors.Wrap(err, "Invalid value for match lines count option")
	}
	if options.matchWordsCount, err = stringz.StringToSliceInt(options.OutputMatchWordsCount); err != nil {
		return errors.Wrap(err, "Invalid value for match words count option")
	}
	if options.filterLinesCount, err = stringz.StringToSliceInt(options.OutputFilterLinesCount); err != nil {
		return errors.Wrap(err, "Invalid value for filter lines count option")
	}
	if options.filterWordsCount, err = stringz.StringToSliceInt(options.OutputFilterWordsCount); err != nil {
		return errors.Wrap(err, "Invalid value for filter words count option")
	}

	var resolvers []string
	for _, resolver := range options.Resolvers {
		if fileutil.FileExists(resolver) {
			chFile, err := fileutil.ReadFile(resolver)
			if err != nil {
				return errors.Wrapf(err, "Couldn't process resolver file \"%s\"", resolver)
			}
			for line := range chFile {
				resolvers = append(resolvers, line)
			}
		} else {
			resolvers = append(resolvers, resolver)
		}
	}

	options.Resolvers = resolvers
	if len(options.Resolvers) > 0 {
		gologger.Debug().Msgf("Using resolvers: %s\n", strings.Join(options.Resolvers, ","))
	}

	if options.Screenshot && !options.StoreResponse {
		gologger.Debug().Msgf("automatically enabling store response")
		options.StoreResponse = true
	}
	if options.StoreResponse && options.StoreResponseDir == "" {
		gologger.Debug().Msgf("Store response directory not specified, using \"%s\"\n", DefaultOutputDirectory)
		options.StoreResponseDir = DefaultOutputDirectory
	}
	if options.StoreResponseDir != "" && !options.StoreResponse {
		gologger.Debug().Msgf("Store response directory specified, enabling \"sr\" flag automatically\n")
		options.StoreResponse = true
	}

	if options.Hashes != "" {
		for _, hashType := range strings.Split(options.Hashes, ",") {
			if !sliceutil.Contains([]string{"md5", "sha1", "sha256", "sha512", "mmh3", "simhash"}, strings.ToLower(hashType)) {
				gologger.Error().Msgf("Unsupported hash type: %s\n", hashType)
			}
		}
	}
	if len(options.OutputMatchCdn) > 0 || len(options.OutputFilterCdn) > 0 {
		options.OutputCDN = "true"
	}

	if !stringsutil.EqualFoldAny(options.Protocol, string(httpx.UNKNOWN), string(httpx.HTTP11)) {
		return fmt.Errorf("invalid protocol: %s", options.Protocol)
	}

	if options.Threads == 0 {
		gologger.Info().Msgf("Threads automatically set to %d", defaultThreads)
		options.Threads = defaultThreads
	}

	return nil
}

// redundant with katana
func (options *Options) ParseHeadlessOptionalArguments() map[string]string {
	var (
		lastKey           string
		optionalArguments = make(map[string]string)
	)
	for _, v := range options.HeadlessOptionalArguments {
		if v == "" {
			continue
		}
		if argParts := strings.SplitN(v, "=", 2); len(argParts) >= 2 {
			key := strings.TrimSpace(argParts[0])
			value := strings.TrimSpace(argParts[1])
			if key != "" && value != "" {
				optionalArguments[key] = value
				lastKey = key
			}
		} else if !strings.HasPrefix(v, "--") {
			optionalArguments[lastKey] += "," + v
		} else {
			optionalArguments[v] = ""
		}
	}
	return optionalArguments
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	if len(options.OutputMatchResponseTime) > 0 || len(options.OutputFilterResponseTime) > 0 {
		options.OutputResponseTime = true
	}
	if options.CSVOutputEncoding != "" {
		options.CSVOutput = true
	}
}

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

func flagsIncompatibleWithSilent(options *Options) []string {
	var incompatibleFlagsList []string
	for k, v := range map[string]bool{
		"debug":          options.Debug,
		"debug-request":  options.DebugRequests,
		"debug-response": options.DebugResponse,
		"verbose":        options.Verbose,
	} {
		if v {
			incompatibleFlagsList = append(incompatibleFlagsList, k)
		}
	}
	return incompatibleFlagsList
}
