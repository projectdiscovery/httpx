package runner

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/go-faker/faker/v4/pkg/options"
	"github.com/mitchellh/mapstructure"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
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
	Timestamp          time.Time              `json:"timestamp,omitempty" csv:"timestamp"`
	ASN                *AsnResponse           `json:"asn,omitempty" csv:"asn"`
	Err                error                  `json:"-" csv:"-"`
	CSPData            *httpx.CSPData         `json:"csp,omitempty" csv:"csp"`
	TLSData            *clients.Response      `json:"tls,omitempty" csv:"tls"`
	Hashes             map[string]interface{} `json:"hash,omitempty" csv:"hash"`
	ExtractRegex       []string               `json:"extract_regex,omitempty" csv:"extract_regex"`
	CDNName            string                 `json:"cdn_name,omitempty" csv:"cdn_name"`
	CDNType            string                 `json:"cdn_type,omitempty" csv:"cdn_type"`
	SNI                string                 `json:"sni,omitempty" csv:"sni"`
	Port               string                 `json:"port,omitempty" csv:"port"`
	Raw                string                 `json:"-" csv:"-"`
	URL                string                 `json:"url,omitempty" csv:"url"`
	Input              string                 `json:"input,omitempty" csv:"input"`
	Location           string                 `json:"location,omitempty" csv:"location"`
	Title              string                 `json:"title,omitempty" csv:"title"`
	str                string
	Scheme             string                 `json:"scheme,omitempty" csv:"scheme"`
	Error              string                 `json:"error,omitempty" csv:"error"`
	WebServer          string                 `json:"webserver,omitempty" csv:"webserver"`
	ResponseBody       string                 `json:"body,omitempty" csv:"body"`
	BodyPreview        string                 `json:"body_preview,omitempty" csv:"body_preview"`
	ContentType        string                 `json:"content_type,omitempty" csv:"content_type"`
	Method             string                 `json:"method,omitempty" csv:"method"`
	Host               string                 `json:"host,omitempty" csv:"host"`
	Path               string                 `json:"path,omitempty" csv:"path"`
	FavIconMMH3        string                 `json:"favicon,omitempty" csv:"favicon"`
	FavIconMD5         string                 `json:"favicon_md5,omitempty" csv:"favicon"`
	FaviconPath        string                 `json:"favicon_path,omitempty" csv:"favicon_path"`
	FaviconURL         string                 `json:"favicon_url,omitempty" csv:"favicon_url"`
	FinalURL           string                 `json:"final_url,omitempty" csv:"final_url"`
	ResponseHeaders    map[string]interface{} `json:"header,omitempty" csv:"header"`
	RawHeaders         string                 `json:"raw_header,omitempty" csv:"raw_header"`
	Request            string                 `json:"request,omitempty" csv:"request"`
	ResponseTime       string                 `json:"time,omitempty" csv:"time"`
	Jarm               string                 `json:"jarm,omitempty" csv:"jarm"`
	ChainStatusCodes   []int                  `json:"chain_status_codes,omitempty" csv:"chain_status_codes"`
	A                  []string               `json:"a,omitempty" csv:"a"`
	AAAA               []string               `json:"aaaa,omitempty" csv:"aaaa"`
	CNAMEs             []string               `json:"cname,omitempty" csv:"cname"`
	Technologies       []string               `json:"tech,omitempty" csv:"tech"`
	Extracts           map[string][]string    `json:"extracts,omitempty" csv:"extracts"`
	Chain              []httpx.ChainItem      `json:"chain,omitempty" csv:"chain"`
	Words              int                    `json:"words" csv:"words"`
	Lines              int                    `json:"lines" csv:"lines"`
	StatusCode         int                    `json:"status_code" csv:"status_code"`
	ContentLength      int                    `json:"content_length" csv:"content_length"`
	Failed             bool                   `json:"failed" csv:"failed"`
	VHost              bool                   `json:"vhost,omitempty" csv:"vhost"`
	WebSocket          bool                   `json:"websocket,omitempty" csv:"websocket"`
	CDN                bool                   `json:"cdn,omitempty" csv:"cdn"`
	HTTP2              bool                   `json:"http2,omitempty" csv:"http2"`
	Pipeline           bool                   `json:"pipeline,omitempty" csv:"pipeline"`
	HeadlessBody       string                 `json:"headless_body,omitempty" csv:"headless_body"`
	ScreenshotBytes    []byte                 `json:"screenshot_bytes,omitempty" csv:"screenshot_bytes"`
	StoredResponsePath string                 `json:"stored_response_path,omitempty" csv:"stored_response_path"`
	ScreenshotPath     string                 `json:"screenshot_path,omitempty" csv:"screenshot_path"`
	ScreenshotPathRel  string                 `json:"screenshot_path_rel,omitempty" csv:"screenshot_path_rel"`
	KnowledgeBase      map[string]interface{} `json:"knowledgebase,omitempty" csv:"knowledgebase"`
	Resolvers          []string               `json:"resolvers,omitempty" csv:"resolvers"`
	Fqdns              []string               `json:"body_fqdn,omitempty"`
	Domains            []string               `json:"body_domains,omitempty"`

	// Internal Fields
	TechnologyDetails map[string]wappalyzer.AppInfo `json:"-" csv:"-"`
	RequestRaw        []byte                        `json:"-" csv:"-"`
	Response          *httpx.Response               `json:"-" csv:"-"`
	FaviconData       []byte                        `json:"-" csv:"-"`
}

// function to get dsl variables from result struct
func dslVariables() ([]string, error) {
	fakeResult := Result{}
	fieldsToIgnore := []string{"Hashes", "ResponseHeaders", "Err", "KnowledgeBase"}
	if err := faker.FakeData(&fakeResult, options.WithFieldsToIgnore(fieldsToIgnore...)); err != nil {
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
		TagName: "json",
		Result:  &m,
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
