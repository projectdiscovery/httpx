package httpx

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// CSPHeaders is an incomplete list of most common CSP headers
var CSPHeaders = []string{
	"Content-Security-Policy",               // standard
	"Content-Security-Policy-Report-Only",   // standard
	"X-Content-Security-Policy-Report-Only", // non - standard
	"X-Webkit-Csp-Report-Only",              // non - standard
}

// CSPData contains the Content-Security-Policy domain list
type CSPData struct {
	Fqdns   []string `json:"fqdn,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

// CSPGrab fills the CSPData
func (h *HTTPX) CSPGrab(r *Response) *CSPData {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})
	// extract from headers
	for _, cspHeader := range CSPHeaders {
		if cspValues, ok := r.Headers[cspHeader]; ok {
			for _, cspValue := range cspValues {
				parsePotentialDomains(fqdns, domains, cspValue)
			}
		}
	}

	// extract from body
	if len(r.Data) > 0 {
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(r.Data))
		if err == nil {
			doc.Find("meta").Each(func(i int, s *goquery.Selection) {
				if _, ok := s.Attr("http-equiv"); ok {
					if content, ok := s.Attr("content"); ok {
						parsePotentialDomains(fqdns, domains, content)
					}
				}
			})
		}
	}

	if len(domains) > 0 || len(fqdns) > 0 {
		return &CSPData{Domains: mapsutil.GetKeys(domains), Fqdns: mapsutil.GetKeys(fqdns)}
	}
	return nil
}

func parsePotentialDomains(fqdns, domains map[string]struct{}, data string) {
	// rule is like aa bb domain1 domain2 domain3
	tokens := stringsutil.SplitAny(data, " ", ";", ",")
	// we extracts only potential domains
	for _, t := range tokens {
		if isPotentialDomain(t) {
			if dn, err := publicsuffix.Parse(extractDomain(t)); err == nil {
				domains[dn.SLD+"."+dn.TLD] = struct{}{}
				if dn.TRD != "" {
					fqdns[dn.String()] = struct{}{}
				}
			}
		}
	}
}

func isPotentialDomain(s string) bool {
	return strings.Contains(s, ".") || strings.HasPrefix(s, "http")
}

func extractDomain(str string) string {
	str = removeWildcards(str)
	u := str
	if !strings.Contains(str, "://") {
		u = "https://" + str
	}
	u = sanitizeURL(u)
	parsedURL, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsedURL.Hostname()
}

func removeWildcards(domain string) string {
	if stringsutil.HasPrefixAny(domain, "'", "\"") {
		domain = domain[1:]
	}
	if stringsutil.HasSuffixAny(domain, "'", "\"") {
		domain = domain[:len(domain)-1]
	}
	if strings.Contains(domain, "://") {
		domain = strings.Split(domain, "://")[1]
	}
	parts := []string{}
	for _, part := range strings.Split(domain, ".") {
		if !strings.Contains(part, "*") {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ".")
}

var urlInvalidCharRegex = regexp.MustCompile(`[^\w-./:~]`)

func sanitizeURL(u string) string {
	// Replace invalid characters with percent-encoded equivalents
	return urlInvalidCharRegex.ReplaceAllStringFunc(u, func(match string) string {
		return fmt.Sprintf("%%%02X", match[0])
	})
}
