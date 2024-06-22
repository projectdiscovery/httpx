package httpx

import (
	"regexp"
	"strings"
	"unicode"

	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

const (
	// group 1 is actual domain regex while group 0 and group 2 are used to filter out invalid matches (by skipping irrelevant contexts)
	potentialDomainRegex = `(?:^|['"/@])` + `([a-z0-9]+[a-z0-9.-]*\.[a-z]{2,})` + `(?:['"/@]|$)`
)

var (
	// potentialDomainsCompiled is a compiled regex for potential domains (aka domain names)
	potentialDomainsCompiled = regexp.MustCompile(potentialDomainRegex)
	defaultDenylist          = []string{".3g2", ".3gp", ".7z", ".apk", ".arj", ".avi", ".axd", ".bmp", ".csv", ".deb", ".dll", ".doc", ".drv", ".eot", ".exe", ".flv", ".gif", ".gifv", ".gz", ".h264", ".ico", ".iso", ".jar", ".jpeg", ".jpg", ".lock", ".m4a", ".m4v", ".map", ".mkv", ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".msi", ".ogg", ".ogm", ".ogv", ".otf", ".pdf", ".pkg", ".png", ".ppt", ".psd", ".rar", ".rm", ".rpm", ".svg", ".swf", ".sys", ".tar.gz", ".tar", ".tif", ".tiff", ".ttf", ".txt", ".vob", ".wav", ".webm", ".webp", ".wmv", ".woff", ".woff2", ".xcf", ".xls", ".xlsx", ".zip", ".css", ".js", ".map", ".php", ".sheet", ".ms", ".wp", ".html", ".htm", ".md"}
	suffixBlacklist          = map[string]struct{}{}
)

type BodyDomain struct {
	Fqdns   []string `json:"body_fqdn,omitempty"`
	Domains []string `json:"body_domains,omitempty"`
}

func (h *HTTPX) BodyDomainGrab(r *Response) *BodyDomain {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	for _, tmp := range potentialDomainsCompiled.FindAllStringSubmatch(r.Raw, -1) {
		// only interested in 1st group
		if len(tmp) < 2 {
			continue
		}
		d := tmp[1]
		// minimal + known blacklist
		if !isValidDomain(d) {
			continue
		}
		// try to parse its tld
		if !isValidTLD(d) {
			continue
		}
		// get domain
		val, err := publicsuffix.Domain(d)
		if err != nil {
			continue
		}
		if r.Input != val {
			domains[val] = struct{}{}
		}
		if d != val && d != r.Input {
			fqdns[d] = struct{}{}
		}
	}

	return &BodyDomain{Domains: mapsutil.GetKeys(domains), Fqdns: mapsutil.GetKeys(fqdns)}
}

func isValidDomain(d string) bool {
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return false
	}
	// this is try when all parts are numeric
	// in which this is not a valid domain (could be a ip or something else)
	allnumeric := true
	// traverse in reverse
	for i := len(parts) - 1; i >= 0; i-- {
		if _, ok := suffixBlacklist["."+parts[i]]; ok {
			return false
		}
		// check for numeric
	local:
		for _, c := range parts[i] {
			if !unicode.IsDigit(c) {
				allnumeric = false
				break local
			}
		}
	}

	if allnumeric {
		// not a domain could be ip or something else
		return false
	}

	// simple hack for android/ios package name
	if stringsutil.HasPrefixAny(d, "com", "net", "io", "org") && !stringsutil.HasSuffixAny(d, "com", "net", "io", "org") {
		return false
	}
	return true
}

func isValidTLD(domain string) bool {
	rule := publicsuffix.DefaultList.Find(domain, publicsuffix.DefaultFindOptions)
	if rule == nil || rule.Type != publicsuffix.NormalType {
		return false
	}

	_, err := publicsuffix.ParseFromListWithOptions(publicsuffix.DefaultList, domain, &publicsuffix.FindOptions{DefaultRule: rule})
	return err == nil
}

func init() {
	for _, s := range defaultDenylist {
		suffixBlacklist[s] = struct{}{}
	}
}
