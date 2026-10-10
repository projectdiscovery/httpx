package runner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

func TestParseTargetLine(t *testing.T) {
	valid := map[string]targetLine{
		`{"target": "https://a.example", "ip": "192.0.2.10"}`: {Target: "https://a.example", IP: "192.0.2.10"},
		`{"target": " a.example:8443 ", "ip": "2001:DB8::1"}`: {Target: "a.example:8443", IP: "2001:db8::1"},
		`{"target": "a.example", "ip": "::ffff:192.0.2.10"}`:  {Target: "a.example", IP: "192.0.2.10"},
		`{"target": "a.example"}`:                             {Target: "a.example"},
	}
	for line, want := range valid {
		t.Run(line, func(t *testing.T) {
			got, err := parseTargetLine(line)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	invalid := map[string]string{
		"malformed json": `{"target": "a.example"`,
		"trailing data":  `{"target": "a.example"} x`,
		"unknown key":    `{"target": "a.example", "ips": "192.0.2.10"}`,
		"missing target": `{"ip": "192.0.2.10"}`,
		"invalid ip":     `{"target": "a.example", "ip": "192.0.2"}`,
		"ip with zone":   `{"target": "a.example", "ip": "fe80::1%eth0"}`,
		"unspecified ip": `{"target": "a.example", "ip": "0.0.0.0"}`,
		"ip target":      `{"target": "https://192.0.2.1", "ip": "192.0.2.10"}`,
		"cidr target":    `{"target": "192.0.2.0/24", "ip": "192.0.2.10"}`,
		"asn target":     `{"target": "AS13335", "ip": "192.0.2.10"}`,
		"wildcard":       `{"target": "*.a.example", "ip": "192.0.2.10"}`,
		"vhost form":     `{"target": "a.example,192.0.2.1", "ip": "192.0.2.10"}`,
	}
	for name, line := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := parseTargetLine(line)
			require.Error(t, err)
		})
	}
}

func TestRunner_normalizeInput(t *testing.T) {
	r := &Runner{options: &Options{}}
	for _, line := range []string{
		`{"target": "https://a.example", "ip": "192.0.2.10"}`,
		` {"ip":"::ffff:192.0.2.10","target":"https://a.example"}`,
	} {
		key, err := r.normalizeInput(line)
		require.NoError(t, err)
		require.Equal(t, `{"target":"https://a.example","ip":"192.0.2.10"}`, key, "equivalent lines are stored once")
	}

	key, err := r.normalizeInput(`{"target": "https://a.example"}`)
	require.NoError(t, err)
	require.Equal(t, "https://a.example", key, "a line without ip is the plain target")

	_, err = r.normalizeInput(`{"target": "https://a.example", "ip": "192.0.2"}`)
	require.Error(t, err)

	r = &Runner{options: &Options{Unsafe: true, Jarm: true}}
	_, err = r.normalizeInput(`{"target": "https://a.example", "ip": "192.0.2.10"}`)
	require.ErrorContains(t, err, "-unsafe, -jarm")
	_, err = r.normalizeInput(`{"target": "https://a.example"}`)
	require.NoError(t, err, "only pinned targets conflict")
}

func TestRunner_targetLine_targets(t *testing.T) {
	// -pa must not resolve a pinned target
	r, err := New(&Options{ProbeAllIPS: true})
	require.NoError(t, err)
	defer r.Close()

	key, err := r.normalizeInput(`{"target": "https://a.example", "ip": "192.0.2.10"}`)
	require.NoError(t, err)
	var got []httpx.Target
	for target := range r.targets(r.hp, key) {
		got = append(got, target)
	}
	require.Equal(t, []httpx.Target{{Host: "https://a.example", CustomIP: "192.0.2.10"}}, got)
}

func TestRunner_streamInput_skipsInvalidLines(t *testing.T) {
	file := filepath.Join(t.TempDir(), "targets.txt")
	lines := "a.example\n" +
		`{"target": "b.example"` + "\n" +
		`{"target": "c.example", "ip": "192.0.2.10"}` + "\n"
	require.NoError(t, os.WriteFile(file, []byte(lines), 0o600))

	r, err := New(&Options{Stream: true, InputFile: file})
	require.NoError(t, err)
	defer r.Close()
	out, err := r.streamInput()
	require.NoError(t, err)

	var got []string
	for item := range out {
		got = append(got, item)
	}
	require.Equal(t, []string{"a.example", `{"target":"c.example","ip":"192.0.2.10"}`}, got, "the malformed line is skipped")
}

// skipIfProxied skips a test whose requests to target go through a proxy set
// in the environment, as the proxy resolves the host itself.
func skipIfProxied(t *testing.T, target string) {
	t.Helper()
	u, err := url.Parse(target)
	require.NoError(t, err)
	if proxy, _ := http.ProxyFromEnvironment(&http.Request{URL: u}); proxy != nil {
		t.Skipf("%s goes through the proxy %s", target, proxy.Redacted())
	}
}

// runPinned probes the target lines with a runner and returns the results.
func runPinned(t *testing.T, lines ...string) []Result {
	t.Helper()

	var (
		mu      sync.Mutex
		results []Result
	)
	r, err := New(&Options{
		Threads:   1,
		RateLimit: 10,
		Timeout:   5,
		Methods:   http.MethodGet,
		Delay:     -1,
		OnResult: func(r Result) {
			if r.Err != nil || r.URL == "" {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
		InputTargetHost: lines,
	})
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()
	return results
}

func TestTargetLinePinsTheConnection(t *testing.T) {
	serve := func(addr, name string) *httptest.Server {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			t.Skipf("cannot listen on %s: %v", addr, err)
		}
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "<title>%s %s</title>", name, r.Host)
		}))
		_ = ts.Listener.Close()
		ts.Listener = listener
		ts.Start()
		t.Cleanup(ts.Close)
		return ts
	}

	one := serve("127.0.0.1:0", "one")
	_, port, err := net.SplitHostPort(one.Listener.Addr().String())
	require.NoError(t, err)
	serve(net.JoinHostPort("127.0.0.2", port), "two")

	target := "http://pinned.test:" + port
	skipIfProxied(t, target)
	results := runPinned(t,
		fmt.Sprintf(`{"target": %q, "ip": "127.0.0.1"}`, target),
		fmt.Sprintf(`{"target": %q, "ip": "127.0.0.2"}`, target),
	)

	var got []string
	for _, result := range results {
		got = append(got, result.HostIP+" "+result.Title)
	}
	sort.Strings(got)
	require.Equal(t, []string{
		"127.0.0.1 one pinned.test:" + port,
		"127.0.0.2 two pinned.test:" + port,
	}, got)
}

func TestTargetLineKeepsSNI(t *testing.T) {
	var (
		mu    sync.Mutex
		names []string
	)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<title>tls</title>")
	}))
	ts.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			names = append(names, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	}
	ts.StartTLS()
	defer ts.Close()
	_, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)

	target := "https://pinned.test:" + port
	skipIfProxied(t, target)
	results := runPinned(t, fmt.Sprintf(`{"target": %q, "ip": "127.0.0.1"}`, target))
	require.Len(t, results, 1)
	require.Equal(t, "127.0.0.1", results[0].HostIP)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, names)
	for _, name := range names {
		require.Equal(t, "pinned.test", name)
	}
}
