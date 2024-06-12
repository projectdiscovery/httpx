package httpx

import (
	"regexp"
	"strings"

	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var (
	domainRegex = `(?i)(?:http?://|[^/\s\"'(]+://)+(?:[^:\s]+:(?:[^:\s]+)@)?(?:(?:[a-z0-9\-.]+\.)+[a-z]{2,}|localhost|(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:\:[0-9]+)?(?:/[^#\s]*)?(?:\?[^#\s]*)?(?:#[^#\s]*)?`
	emailRegex  = `(?i)[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`
)

type BodyDomain struct {
	Fqdns   []string `json:"body_fqdn,omitempty"`
	Domains []string `json:"body_domains,omitempty"`
}

func (h *HTTPX) BodyDomainGrab(r *Response) *BodyDomain {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})
	uniqueDomains := make(map[string]struct{})

	re := regexp.MustCompile(domainRegex)
	for _, d := range re.FindAllString(r.Raw, -1) {
		uniqueDomains[d] = struct{}{}
	}

	re = regexp.MustCompile(emailRegex)
	for _, d := range re.FindAllString(r.Raw, -1) {
		uniqueDomains[strings.Split(d, "@")[1]] = struct{}{}
	}

	for d := range uniqueDomains {
		if dn, err := publicsuffix.Parse(extractDomain(d)); err == nil {
			domains[dn.SLD+"."+dn.TLD] = struct{}{}
			if dn.TRD != "" {
				fqdns[dn.String()] = struct{}{}
			}
		}
	}

	return &BodyDomain{Domains: mapsutil.GetKeys(domains), Fqdns: mapsutil.GetKeys(fqdns)}
}
