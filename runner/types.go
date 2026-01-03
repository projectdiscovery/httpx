package runner

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/go-faker/faker/v4/pkg/options"
	mapstructure "github.com/go-viper/mapstructure/v2"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	mapsutil "github.com/projectdiscovery/utils/maps"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/projectdiscovery/httpx/common/httpx"
)

type AsnResponse struct {
	AsNumber  string   `json:"as_number" csv:"as_number"`
	AsName    string   `json:"as_name" csv:"as_name"`
	AsCountry string   `json:"as_country" csv:"as_country"`
	AsRange   []string `json:"as_range" csv:"as_range"`
}

func (o AsnResponse) String() string {
	return fmt.Sprintf("%v, %v, %v", o.AsNumber, o.AsName, o.AsCountry)
}

// Result of a scan
type Result struct {
	Timestamp          time.Time                     `json:"timestamp,omitempty" csv:"timestamp" md:"timestamp" mapstructure:"timestamp"`
	LinkRequest        []NetworkRequest              `json:"link_request,omitempty" csv:"link_request" md:"link_request" mapstructure:"link_request"`
	ASN                *AsnResponse                  `json:"asn,omitempty" csv:"-" md:"-" mapstructure:"asn"`
	Err                error                         `json:"-" csv:"-" md:"-" mapstructure:"-"`
	CSPData            *httpx.CSPData                `json:"csp,omitempty" csv:"-" md:"-" mapstructure:"csp"`
	TLSData            *clients.Response             `json:"tls,omitempty" csv:"-" md:"-" mapstructure:"tls"`
	Hashes             map[string]interface{}        `json:"hash,omitempty" csv:"-" md:"-" mapstructure:"hash"`
	ExtractRegex       []string                      `json:"extract_regex,omitempty" csv:"extract_regex" md:"extract_regex" mapstructure:"extract_regex"`
	CDNName            string                        `json:"cdn_name,omitempty" csv:"cdn_name" md:"cdn_name" mapstructure:"cdn_name"`
	CDNType            string                        `json:"cdn_type,omitempty" csv:"cdn_type" md:"cdn_type" mapstructure:"cdn_type"`
	SNI                string                        `json:"sni,omitempty" csv:"sni" md:"sni" mapstructure:"sni"`
	Port               string                        `json:"port,omitempty" csv:"port" md:"port" mapstructure:"port"`
	Raw                string                        `json:"-" csv:"-" md:"-" mapstructure:"-"`
	URL                string                        `json:"url,omitempty" csv:"url" md:"url" mapstructure:"url"`
	Input              string                        `json:"input,omitempty" csv:"input" md:"input" mapstructure:"input"`
	Location           string                        `json:"location,omitempty" csv:"location" md:"location" mapstructure:"location"`
	Title              string                        `json:"title,omitempty" csv:"title" md:"title" mapstructure:"title"`
	str                string                        `json:"-" csv:"-" md:"-" mapstructure:"-"`
	Scheme             string                        `json:"scheme,omitempty" csv:"scheme" md:"scheme" mapstructure:"scheme"`
	Error              string                        `json:"error,omitempty" csv:"error" md:"error" mapstructure:"error"`
	WebServer          string                        `json:"webserver,omitempty" csv:"webserver" md:"webserver" mapstructure:"webserver"`
	ResponseBody       string                        `json:"body,omitempty" csv:"-" md:"-" mapstructure:"body"`
	BodyPreview        string                        `json:"body_preview,omitempty" csv:"body_preview" md:"body_preview" mapstructure:"body_preview"`
	ContentType        string                        `json:"content_type,omitempty" csv:"content_type" md:"content_type" mapstructure:"content_type"`
	Method             string                        `json:"method,omitempty" csv:"method" md:"method" mapstructure:"method"`
	Host               string                        `json:"host,omitempty" csv:"host" md:"host" mapstructure:"host"`
	HostIP             string                        `json:"host_ip,omitempty" csv:"host_ip" md:"host_ip" mapstructure:"host_ip"`
	Path               string                        `json:"path,omitempty" csv:"path" md:"path" mapstructure:"path"`
	FavIconMMH3        string                        `json:"favicon,omitempty" csv:"favicon" md:"favicon" mapstructure:"favicon"`
	FavIconMD5         string                        `json:"favicon_md5,omitempty" csv:"favicon_md5" md:"favicon_md5" mapstructure:"favicon_md5"`
	FaviconPath        string                        `json:"favicon_path,omitempty" csv:"favicon_path" md:"favicon_path" mapstructure:"favicon_path"`
	FaviconURL         string                        `json:"favicon_url,omitempty" csv:"favicon_url" md:"favicon_url" mapstructure:"favicon_url"`
	FinalURL           string                        `json:"final_url,omitempty" csv:"final_url" md:"final_url" mapstructure:"final_url"`
	ResponseHeaders    map[string]interface{}        `json:"header,omitempty" csv:"-" md:"-" mapstructure:"header"`
	RawHeaders         string                        `json:"raw_header,omitempty" csv:"-" md:"-" mapstructure:"raw_header"`
	Request            string                        `json:"request,omitempty" csv:"-" md:"-" mapstructure:"request"`
	ResponseTime       string                        `json:"time,omitempty" csv:"time" md:"time" mapstructure:"time"`
	JarmHash           string                        `json:"jarm_hash,omitempty" csv:"jarm_hash" md:"jarm_hash" mapstructure:"jarm_hash"`
	ChainStatusCodes   []int                         `json:"chain_status_codes,omitempty" csv:"chain_status_codes" md:"chain_status_codes" mapstructure:"chain_status_codes"`
	A                  []string                      `json:"a,omitempty" csv:"a" md:"a" mapstructure:"a"`
	AAAA               []string                      `json:"aaaa,omitempty" csv:"aaaa" md:"aaaa" mapstructure:"aaaa"`
	CNAMEs             []string                      `json:"cname,omitempty" csv:"cname" md:"cname" mapstructure:"cname"`
	Technologies       []string                      `json:"tech,omitempty" csv:"tech" md:"tech" mapstructure:"tech"`
	Extracts           map[string][]string           `json:"extracts,omitempty" csv:"-" md:"-" mapstructure:"extracts"`
	Chain              []httpx.ChainItem             `json:"chain,omitempty" csv:"-" md:"-" mapstructure:"chain"`
	Words              int                           `json:"words" csv:"words" md:"words" mapstructure:"words"`
	Lines              int                           `json:"lines" csv:"lines" md:"lines" mapstructure:"lines"`
	StatusCode         int                           `json:"status_code" csv:"status_code" md:"status_code" mapstructure:"status_code"`
	ContentLength      int                           `json:"content_length" csv:"content_length" md:"content_length" mapstructure:"content_length"`
	Failed             bool                          `json:"failed" csv:"failed" md:"failed" mapstructure:"failed"`
	VHost              bool                          `json:"vhost,omitempty" csv:"vhost" md:"vhost" mapstructure:"vhost"`
	WebSocket          bool                          `json:"websocket,omitempty" csv:"websocket" md:"websocket" mapstructure:"websocket"`
	CDN                bool                          `json:"cdn,omitempty" csv:"cdn" md:"cdn" mapstructure:"cdn"`
	HTTP2              bool                          `json:"http2,omitempty" csv:"http2" md:"http2" mapstructure:"http2"`
	Pipeline           bool                          `json:"pipeline,omitempty" csv:"pipeline" md:"pipeline" mapstructure:"pipeline"`
	HeadlessBody       string                        `json:"headless_body,omitempty" csv:"headless_body" md:"headless_body" mapstructure:"headless_body"`
	ScreenshotBytes    []byte                        `json:"screenshot_bytes,omitempty" csv:"screenshot_bytes" md:"screenshot_bytes" mapstructure:"screenshot_bytes"`
	StoredResponsePath string                        `json:"stored_response_path,omitempty" csv:"stored_response_path" md:"stored_response_path" mapstructure:"stored_response_path"`
	ScreenshotPath     string                        `json:"screenshot_path,omitempty" csv:"screenshot_path" md:"screenshot_path" mapstructure:"screenshot_path"`
	ScreenshotPathRel  string                        `json:"screenshot_path_rel,omitempty" csv:"screenshot_path_rel" md:"screenshot_path_rel" mapstructure:"screenshot_path_rel"`
	KnowledgeBase      map[string]interface{}        `json:"knowledgebase,omitempty" csv:"-" md:"-" mapstructure:"knowledgebase"`
	Resolvers          []string                      `json:"resolvers,omitempty" csv:"resolvers" md:"resolvers" mapstructure:"resolvers"`
	Fqdns              []string                      `json:"body_fqdn,omitempty" csv:"body_fqdn" md:"body_fqdn" mapstructure:"body_fqdn"`
	Domains            []string                      `json:"body_domains,omitempty" csv:"body_domains" md:"body_domains" mapstructure:"body_domains"`
	TechnologyDetails  map[string]wappalyzer.AppInfo `json:"-" csv:"-" md:"-" mapstructure:"-"`
	RequestRaw         []byte                        `json:"-" csv:"-" md:"-" mapstructure:"-"`
	Response           *httpx.Response               `json:"-" csv:"-" md:"-" mapstructure:"-"`
	FaviconData        []byte                        `json:"-" csv:"-" md:"-" mapstructure:"-"`
	Trace              *retryablehttp.TraceInfo      `json:"trace,omitempty" csv:"-" md:"-" mapstructure:"trace"`
}

type Trace struct {
	GetConn              time.Time `json:"get_conn,omitempty"`
	GotConn              time.Time `json:"got_conn,omitempty"`
	PutIdleConn          time.Time `json:"put_idle_conn,omitempty"`
	GotFirstResponseByte time.Time `json:"got_first_response_byte,omitempty"`
	Got100Continue       time.Time `json:"got_100_continue,omitempty"`
	DNSStart             time.Time `json:"dns_start,omitempty"`
	DNSDone              time.Time `json:"dns_done,omitempty"`
	ConnectStart         time.Time `json:"connect_start,omitempty"`
	ConnectDone          time.Time `json:"connect_done,omitempty"`
	TLSHandshakeStart    time.Time `json:"tls_handshake_start,omitempty"`
	TLSHandshakeDone     time.Time `json:"tls_handshake_done,omitempty"`
	WroteHeaderField     time.Time `json:"wrote_header_field,omitempty"`
	WroteHeaders         time.Time `json:"wrote_headers,omitempty"`
	Wait100Continue      time.Time `json:"wait_100_continue,omitempty"`
	WroteRequest         time.Time `json:"wrote_request,omitempty"`
}

// function to get dsl variables from result struct
func dslVariables() ([]string, error) {
	fakeResult := Result{}
	fieldsToIgnore := []string{"Hashes", "ResponseHeaders", "Err", "KnowledgeBase"}
	if err := faker.FakeData(&fakeResult, options.WithFieldsToIgnore(fieldsToIgnore...), options.WithIgnoreInterface(true)); err != nil {
		return nil, err
	}
	m, err := resultToMap(fakeResult)
	if err != nil {
		return nil, err
	}
	vars := []string{"header_md5", "header_mmh3", "header_sha256", "header_simhash", "body_md5", "body_mmh3", "body_sha256", "body_simhash"}
	mapsutil.Walk(m, func(k string, v any) {
		vars = append(vars, k)
	})

	return vars, nil
}

func evalDslExpr(result Result, dslExpr string) bool {
	resultMap, err := resultToMap(result)
	if err != nil {
		gologger.Warning().Msgf("Could not map result: %s\n", err)
		return false
	}

	res, err := dsl.EvalExpr(dslExpr, resultMap)
	if err != nil && !ignoreErr(err) {
		gologger.Error().Msgf("Could not evaluate DSL expression: %s\n", err)
		return false
	}
	return res == true
}

func resultToMap(resp Result) (map[string]any, error) {
	m := make(map[string]any)
	config := &mapstructure.DecoderConfig{
		Result: &m,
	}
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return nil, fmt.Errorf("error creating decoder: %v", err)
	}
	err = decoder.Decode(resp)
	if err != nil {
		return nil, fmt.Errorf("error decoding: %v", err)
	}
	return m, nil
}

var (
	// showDSLErr controls whether to show hidden DSL errors or not
	showDSLErr = strings.EqualFold(os.Getenv("SHOW_DSL_ERRORS"), "true")
)

// ignoreErr checks if the error is to be ignored or not
func ignoreErr(err error) bool {
	if showDSLErr {
		return false
	}
	if errors.Is(err, dsl.ErrParsingArg) || strings.Contains(err.Error(), "No parameter") {
		return true
	}
	return false
}
