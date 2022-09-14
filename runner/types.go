package runner

import (
	"fmt"
	"time"

	"github.com/projectdiscovery/cryptoutil"
	"github.com/projectdiscovery/httpx/common/httpx"
)

// List of all dsl variables
var dslVariables = []string{"timestamp", "csp", "domains", "hash", "body_md5", "body_mmh3", "body_sha256", "body_simhash", "header_md5", "header_mmh3", "header_sha256", "header_simhash", "port", "url", "input", "location",  "scheme", "webserver", "content-type", "method", "host", "path", "a", "words", "lines", "status_code", "content_length", "failed", "time", "body", "header", "request"}

type AsnResponse struct {
	AsNumber  string `json:"as-number" csv:"as-number"`
	AsName    string `json:"as-name" csv:"as-name"`
	AsCountry string `json:"as-country" csv:"as-country"`
	AsRange   string `json:"as-range" csv:"as-range"`
}

func (o AsnResponse) String() string {
	return fmt.Sprintf("%v, %v, %v, %v", o.AsNumber, o.AsName, o.AsCountry, o.AsRange)
}

// Result of a scan
type Result struct {
	Timestamp        time.Time   `json:"timestamp,omitempty" csv:"timestamp"`
	ASN              interface{} `json:"asn,omitempty" csv:"asn"`
	err              error
	CSPData          *httpx.CSPData      `json:"csp,omitempty" csv:"csp"`
	TLSData          *cryptoutil.TLSData `json:"tls,omitempty" csv:"tls"`
	Hashes           map[string]string   `json:"hash,omitempty" csv:"hash"`
	ExtractRegex     []string            `json:"extract_regex,omitempty" csv:"extract_regex"`
	CDNName          string              `json:"cdn_name,omitempty" csv:"cdn_name"`
	Port             string              `json:"port,omitempty" csv:"port"`
	raw              string
	URL              string `json:"url,omitempty" csv:"url"`
	Input            string `json:"input,omitempty" csv:"input"`
	Location         string `json:"location,omitempty" csv:"location"`
	Title            string `json:"title,omitempty" csv:"title"`
	str              string
	Scheme           string              `json:"scheme,omitempty" csv:"scheme"`
	Error            string              `json:"error,omitempty" csv:"error"`
	WebServer        string              `json:"webserver,omitempty" csv:"webserver"`
	ResponseBody     string              `json:"body,omitempty" csv:"body"`
	ContentType      string              `json:"content_type,omitempty" csv:"content_type"`
	Method           string              `json:"method,omitempty" csv:"method"`
	Host             string              `json:"host,omitempty" csv:"host"`
	Path             string              `json:"path,omitempty" csv:"path"`
	FavIconMMH3      string              `json:"favicon,omitempty" csv:"favicon"`
	FinalURL         string              `json:"final_url,omitempty" csv:"final_url"`
	ResponseHeader   string              `json:"header,omitempty" csv:"header"`
	Request          string              `json:"request,omitempty" csv:"request"`
	ResponseTime     string              `json:"time,omitempty" csv:"time"`
	Jarm             string              `json:"jarm,omitempty" csv:"jarm"`
	ChainStatusCodes []int               `json:"chain_status_codes,omitempty" csv:"chain_status_codes"`
	A                []string            `json:"a,omitempty" csv:"a"`
	CNAMEs           []string            `json:"cname,omitempty" csv:"cname"`
	Technologies     []string            `json:"tech,omitempty" csv:"tech"`
	Extracts         map[string][]string `json:"extracts,omitempty" csv:"extracts"`
	Chain            []httpx.ChainItem   `json:"chain,omitempty" csv:"chain"`
	Words            int                 `json:"words" csv:"words"`
	Lines            int                 `json:"lines" csv:"lines"`
	StatusCode       int                 `json:"status_code,omitempty" csv:"status_code"`
	ContentLength    int                 `json:"content_length,omitempty" csv:"content_length"`
	Failed           bool                `json:"failed" csv:"failed"`
	VHost            bool                `json:"vhost,omitempty" csv:"vhost"`
	WebSocket        bool                `json:"websocket,omitempty" csv:"websocket"`
	CDN              bool                `json:"cdn,omitempty" csv:"cdn"`
	HTTP2            bool                `json:"http2,omitempty" csv:"http2"`
	Pipeline         bool                `json:"pipeline,omitempty" csv:"pipeline"`
}
