package httpx

import (
	"net/http"
	"strings"
)

type CspData struct {
	Domains []string `json:"domains,omitempty"`
}

func (h *HTTPX) CspGrab(r *http.Response) *CspData {
	cspRaw := r.Header.Get("Content-Security-Policy")
	if cspRaw != "" {
		var domains []string
		rules := strings.Split(cspRaw, ";")
		for _, rule := range rules {
			// rule is like aa bb domain1 domain2 domain3
			tokens := strings.Split(rule, " ")
			// we extracts only potential domains
			for _, t := range tokens {
				if isPotentialDomain(t) {
					domains = append(domains, t)
				}
			}
		}
		return &CspData{Domains: domains}
	}
	return nil
}

// bare minimum conditions to filter potential domains
func isPotentialDomain(s string) bool {
	return strings.Contains(s, ".") || strings.HasPrefix(s, "http")
}
