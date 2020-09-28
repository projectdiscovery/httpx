package httpx

import (
	"net/http"
	"strings"

	"github.com/projectdiscovery/httpx/common/slice"
)

// CSPHeaders is an incomplete list of most common CSP headers
var CSPHeaders []string = []string{
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
func (h *HTTPX) CSPGrab(r *http.Response) *CSPData {
	domains := make(map[string]struct{})
	for _, cspHeader := range CSPHeaders {
		cspRaw := r.Header.Get(cspHeader)
		if cspRaw != "" {
			rules := strings.Split(cspRaw, ";")
			for _, rule := range rules {
				// rule is like aa bb domain1 domain2 domain3
				tokens := strings.Split(rule, " ")
				// we extracts only potential domains
				for _, t := range tokens {
					if isPotentialDomain(t) {
						domains[t] = struct{}{}
					}
				}
			}
		}
	}

	if len(domains) > 0 {
		return &CSPData{Domains: slice.ToSlice(domains)}
	}
	return nil
}

func isPotentialDomain(s string) bool {
	return strings.Contains(s, ".") || strings.HasPrefix(s, "http")
}
