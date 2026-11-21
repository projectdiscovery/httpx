package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/common/authprovider/authx"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

// mockAuthProvider is a simple in-memory AuthProvider for tests
type mockAuthProvider struct {
	strategies map[string][]authx.AuthStrategy
}

func (m *mockAuthProvider) LookupAddr(addr string) []authx.AuthStrategy {
	return m.strategies[addr]
}

func (m *mockAuthProvider) LookupURL(u *url.URL) []authx.AuthStrategy {
	host := u.Hostname()
	if s, ok := m.strategies[host]; ok {
		return s
	}
	return m.strategies[u.Host]
}

func (m *mockAuthProvider) LookupURLX(u *urlutil.URL) []authx.AuthStrategy {
	host := u.Host
	if s, ok := m.strategies[host]; ok {
		return s
	}
	return nil
}

func TestRedirect_CustomCookies_NotLeakedToOtherHost(t *testing.T) {
	var targetCookieReceived string

	// Target server (different host)
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCookieReceived = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("target ok"))
	}))
	defer targetServer.Close()

	// Initial server redirects to targetServer
	initialServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer initialServer.Close()

	options := DefaultOptions
	options.FollowRedirects = true
	options.Timeout = 5 * time.Second
	options.CustomHeaders = map[string][]string{
		"Cookie": {"session=secret123"},
	}

	client, err := New(&options)
	require.NoError(t, err)

	req, err := retryablehttp.NewRequest("GET", strings.Replace(initialServer.URL, "127.0.0.1", "localhost", 1), nil)
	require.NoError(t, err)
	client.SetCustomHeaders(req, client.CustomHeaders)

	resp, err := client.Do(req, UnsafeOptions{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the target server did NOT receive the custom cookie
	require.Empty(t, targetCookieReceived, "custom cookie should not be leaked on redirect to different host")
}

func TestRedirect_CustomCookies_PreservedOnSameHost(t *testing.T) {
	var targetCookieReceived string

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, ts.URL+"/target", http.StatusFound)
			return
		}
		targetCookieReceived = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	options := DefaultOptions
	options.FollowRedirects = true
	options.Timeout = 5 * time.Second
	options.CustomHeaders = map[string][]string{
		"Cookie": {"session=secret123"},
	}

	client, err := New(&options)
	require.NoError(t, err)

	req, err := retryablehttp.NewRequest("GET", ts.URL+"/redirect", nil)
	require.NoError(t, err)
	client.SetCustomHeaders(req, client.CustomHeaders)

	resp, err := client.Do(req, UnsafeOptions{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the same-host target DID receive the custom cookie
	require.Contains(t, targetCookieReceived, "session=secret123", "custom cookie should be preserved on same host redirect")
}

func TestRedirect_AuthProvider_HeadersAppliedPerHostRules(t *testing.T) {
	var targetAuthHeaderReceived string

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetAuthHeaderReceived = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("target ok"))
	}))
	defer targetServer.Close()

	initialServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer initialServer.Close()

	initialHost := initialServer.Listener.Addr().String()
	targetHost := targetServer.Listener.Addr().String()
	initialHostname := strings.Split(initialHost, ":")[0]
	targetHostname := strings.Split(targetHost, ":")[0]

	// Configure mock auth provider:
	// initialServer has secret "initial-secret", targetServer has secret "target-secret"
	mockAuth := &mockAuthProvider{
		strategies: map[string][]authx.AuthStrategy{
			initialHost: {
				authx.NewHeadersAuthStrategy(&authx.Secret{
					Headers: []authx.KV{{Key: "X-Api-Key", Value: "initial-secret"}},
				}),
			},
			initialHostname: {
				authx.NewHeadersAuthStrategy(&authx.Secret{
					Headers: []authx.KV{{Key: "X-Api-Key", Value: "initial-secret"}},
				}),
			},
			targetHost: {
				authx.NewHeadersAuthStrategy(&authx.Secret{
					Headers: []authx.KV{{Key: "X-Api-Key", Value: "target-secret"}},
				}),
			},
			targetHostname: {
				authx.NewHeadersAuthStrategy(&authx.Secret{
					Headers: []authx.KV{{Key: "X-Api-Key", Value: "target-secret"}},
				}),
			},
		},
	}

	options := DefaultOptions
	options.FollowRedirects = true
	options.Timeout = 5 * time.Second
	options.AuthProvider = mockAuth

	client, err := New(&options)
	require.NoError(t, err)

	req, err := retryablehttp.NewRequest("GET", initialServer.URL, nil)
	require.NoError(t, err)

	// Apply initial strategies
	if strategies := mockAuth.LookupURL(req.URL.URL); len(strategies) > 0 {
		for _, s := range strategies {
			s.ApplyOnRR(req)
		}
	}

	resp, err := client.Do(req, UnsafeOptions{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The target host must receive target-secret, NOT initial-secret!
	require.Equal(t, "target-secret", targetAuthHeaderReceived, "redirect host should receive its own auth secret")
}

func TestRedirect_QueryAuth_TargetParamPreserved(t *testing.T) {
	var targetQueryToken string

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetQueryToken = r.URL.Query().Get("token")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer targetServer.Close()

	initialServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL+"?token=target-token", http.StatusFound)
	}))
	defer initialServer.Close()

	initialHost := initialServer.Listener.Addr().String()

	// Initial server has a query auth strategy for "token"
	mockAuth := &mockAuthProvider{
		strategies: map[string][]authx.AuthStrategy{
			initialHost: {
				authx.NewQueryAuthStrategy(&authx.Secret{
					Params: []authx.KV{{Key: "token", Value: "initial-token"}},
				}),
			},
		},
	}

	options := DefaultOptions
	options.FollowRedirects = true
	options.Timeout = 5 * time.Second
	options.AuthProvider = mockAuth

	client, err := New(&options)
	require.NoError(t, err)

	req, err := retryablehttp.NewRequest("GET", initialServer.URL, nil)
	require.NoError(t, err)

	if strategies := mockAuth.LookupURL(req.URL.URL); len(strategies) > 0 {
		for _, s := range strategies {
			s.ApplyOnRR(req)
		}
	}

	resp, err := client.Do(req, UnsafeOptions{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Target token provided by Location redirect must be preserved
	require.Equal(t, "target-token", targetQueryToken)
}

// A -H cookie that shares its name with a secret-file cookie must survive a
// same-host redirect to a URL the secret does not cover: the secret cleanup
// removes cookies by name, and the -H cookie has to come back after it.
func TestRedirect_CustomCookie_KeptWhenSameNameSecretRemoved(t *testing.T) {
	var targetCookies []*http.Cookie
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCookies = r.Cookies()
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	initialServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer initialServer.Close()

	// the secret covers only the initial server's host:port
	mockAuth := &mockAuthProvider{
		strategies: map[string][]authx.AuthStrategy{
			initialServer.Listener.Addr().String(): {
				authx.NewCookiesAuthStrategy(&authx.Secret{
					Cookies: []authx.Cookie{{Key: "shared", Value: "SECRET-VALUE"}},
				}),
			},
		},
	}

	options := DefaultOptions
	options.FollowRedirects = true
	options.Timeout = 5 * time.Second
	options.AuthProvider = mockAuth
	options.CustomHeaders = map[string][]string{
		"Cookie": {"shared=H-VALUE"},
	}

	client, err := New(&options)
	require.NoError(t, err)

	req, err := retryablehttp.NewRequest("GET", initialServer.URL, nil)
	require.NoError(t, err)
	client.SetCustomHeaders(req, client.CustomHeaders)
	for _, s := range mockAuth.LookupURL(req.URL.URL) {
		s.ApplyOnRR(req)
	}

	resp, err := client.Do(req, UnsafeOptions{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	var values []string
	for _, c := range targetCookies {
		if c.Name == "shared" {
			values = append(values, c.Value)
		}
	}
	require.Equal(t, []string{"H-VALUE"}, values, "redirect target cookies: %v", targetCookies)
}
