package authprovider

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/projectdiscovery/httpx/common/authprovider/authx"
	"github.com/projectdiscovery/utils/errkit"
	urlutil "github.com/projectdiscovery/utils/url"
)

// FileAuthProvider is an auth provider for file based auth
// it accepts a secrets file and returns its provider
type FileAuthProvider struct {
	Path     string
	store    *authx.Authx
	compiled map[*regexp.Regexp][]authx.AuthStrategy
	domains  map[string][]authx.AuthStrategy
}

// NewFileAuthProvider creates a new file based auth provider
func NewFileAuthProvider(path string) (AuthProvider, error) {
	store, err := authx.GetAuthDataFromFile(path)
	if err != nil {
		return nil, err
	}
	if len(store.Secrets) == 0 {
		return nil, ErrNoSecrets
	}
	for _, secret := range store.Secrets {
		if err := secret.Validate(); err != nil {
			errorErr := errkit.FromError(err)
			errorErr.Msgf("invalid secret in file: %s", path)
			return nil, errorErr
		}
	}
	f := &FileAuthProvider{Path: path, store: store}
	f.init()
	return f, nil
}

// init initializes the file auth provider
func (f *FileAuthProvider) init() {
	for _, _secret := range f.store.Secrets {
		secret := _secret // capture loop variable for use in GetStrategy()
		if len(secret.DomainsRegex) > 0 {
			for _, domain := range secret.DomainsRegex {
				if f.compiled == nil {
					f.compiled = make(map[*regexp.Regexp][]authx.AuthStrategy)
				}
				compiled, err := regexp.Compile(domain)
				if err != nil {
					continue
				}

				if ss, ok := f.compiled[compiled]; ok {
					f.compiled[compiled] = append(ss, secret.GetStrategy())
				} else {
					f.compiled[compiled] = []authx.AuthStrategy{secret.GetStrategy()}
				}
			}
		}
		for _, domain := range secret.Domains {
			if f.domains == nil {
				f.domains = make(map[string][]authx.AuthStrategy)
			}
			domain = strings.TrimSpace(domain)
			domain = strings.TrimSuffix(domain, ":80")
			domain = strings.TrimSuffix(domain, ":443")
			if ss, ok := f.domains[domain]; ok {
				f.domains[domain] = append(ss, secret.GetStrategy())
			} else {
				f.domains[domain] = []authx.AuthStrategy{secret.GetStrategy()}
			}
		}
	}
}

// LookupAddr looks up a given domain/address and returns appropriate auth strategy
func (f *FileAuthProvider) LookupAddr(addr string) []authx.AuthStrategy {
	var strategies []authx.AuthStrategy

	if strings.Contains(addr, ":") {
		// strip default ports (80/443) for consistent domain matching
		host, port, err := net.SplitHostPort(addr)
		if err == nil && (port == "80" || port == "443") {
			addr = host
		}
	}
	for domain, strategy := range f.domains {
		if strings.EqualFold(domain, addr) {
			strategies = append(strategies, strategy...)
		}
	}
	for compiled, strategy := range f.compiled {
		if compiled.MatchString(addr) {
			strategies = append(strategies, strategy...)
		}
	}

	return strategies
}

// LookupURL looks up a given URL and returns appropriate auth strategy
func (f *FileAuthProvider) LookupURL(u *url.URL) []authx.AuthStrategy {
	return f.LookupAddr(u.Host)
}

// LookupURLX looks up a given URL and returns appropriate auth strategy
func (f *FileAuthProvider) LookupURLX(u *urlutil.URL) []authx.AuthStrategy {
	return f.LookupAddr(u.Host)
}
