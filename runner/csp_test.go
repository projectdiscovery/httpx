package runner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// -csp-probe probes the domains of the Content-Security-Policy, so it must
// have them extracted without -efqdn, which also adds the domains of the body.
func TestCSPProbeExtractsCSPDomains(t *testing.T) {
	r, err := New(&Options{CSPProbe: true})
	require.NoError(t, err)
	defer r.Close()
	require.True(t, r.hp.Options.ExtractCSP)
	require.False(t, r.hp.Options.ExtractFqdn)
}

// Every input with a CSP gets its CSP domains probed, not only the first one,
// even though the probes of the first one turn -csp-probe off for themselves.
func TestCSPProbeProbesCSPDomainsOfEveryTarget(t *testing.T) {
	cspServer := func(domain string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Security-Policy", "default-src 'self' https://cdn."+domain)
		}))
		t.Cleanup(srv.Close)
		return strings.TrimPrefix(srv.URL, "http://")
	}

	options := &Options{
		Threads:         5,
		RateLimit:       100,
		Retries:         0,
		Timeout:         2,
		Methods:         http.MethodGet,
		Delay:           -1,
		CSPProbe:        true,
		InputTargetHost: []string{cspServer("csp-one.invalid"), cspServer("csp-two.invalid")},
	}

	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	for _, domain := range []string{"csp-one.invalid", "cdn.csp-one.invalid", "csp-two.invalid", "cdn.csp-two.invalid"} {
		require.True(t, r.seen(domain), "CSP domain %s was not probed", domain)
	}
}
