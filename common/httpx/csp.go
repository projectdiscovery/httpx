package httpx

import (
	"bytes"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/httpx/common/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
	Domains []string `json:"domains,omitempty"`
}

// CSPGrab fills the CSPData
func (h *HTTPX) CSPGrab(r *Response) *CSPData {
	domains := make(map[string]struct{})
	// extract from headers
	for _, cspHeader := range CSPHeaders {
		if cspValues, ok := r.Headers[cspHeader]; ok {
			for _, cspValue := range cspValues {
				parsePotentialDomains(domains, cspValue)
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
						parsePotentialDomains(domains, content)
					}
				}
			})
		}
	}

	if len(domains) > 0 {
		return &CSPData{Domains: slice.ToSlice(domains)}
	}
	return nil
}

func parsePotentialDomains(domains map[string]struct{}, data string) {
	// rule is like aa bb domain1 domain2 domain3
	tokens := stringsutil.SplitAny(data, " ", ";", ",")
	// we extracts only potential domains
	for _, t := range tokens {
		if isPotentialDomain(t) {
			domains[t] = struct{}{}
		}
	}
}

func isPotentialDomain(s string) bool {
	return strings.Contains(s, ".") || strings.HasPrefix(s, "http")
}
