package httpx

import (
	"regexp"

	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var (
	domainRegex = `(?i)(?:http?://|[a-z]+://)+(?:[^:\s]+:(?:[^:\s]+)@)?((?:[a-z0-9\-.]+\.)+[a-z]{2,})(?:\:[0-9]+)?(?:/[^#\s'"\);]*)?(?:\?[^#\s"'\);]*)?(?:#[^#\s"'\);]*)? | (?i)\b(?:(?:[a-z0-9\-.]+\.)+[a-z]{2,}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})|\b(?:[a-z0-9\-.]+\.)+[a-z]{2,}(?:\/[^\s#?"');]*)?\b`
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

	for d := range uniqueDomains {
		d = extractDomain(d)
		rule := publicsuffix.DefaultList.Find(d, publicsuffix.DefaultFindOptions)
		if rule == nil || rule.Type != publicsuffix.NormalType {
			continue
		}
		if dn, err := publicsuffix.ParseFromListWithOptions(publicsuffix.DefaultList, d, &publicsuffix.FindOptions{DefaultRule: rule}); err == nil {
			domains[dn.SLD+"."+dn.TLD] = struct{}{}
			if dn.TRD != "" {
				fqdns[dn.String()] = struct{}{}
			}
		}
	}

	return &BodyDomain{Domains: mapsutil.GetKeys(domains), Fqdns: mapsutil.GetKeys(fqdns)}
}
