package runner

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
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

	r = &Runner{options: &Options{Unsafe: true, Jarm: true, Protocol: "HTTP2"}}
	_, err = r.normalizeInput(`{"target": "https://a.example", "ip": "192.0.2.10"}`)
	require.ErrorContains(t, err, "-unsafe, -pr http2, -jarm")
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

// A proxy, set with -proxy for -pa or in the environment, resolves the host
// itself, so a probe of a pinned target through it fails.
func TestRunner_analyze_pinnedThroughProxy(t *testing.T) {
	r, err := New(&Options{HTTPProxy: "http://127.0.0.1:1"})
	require.NoError(t, err)
	defer r.Close()

	target := httpx.Target{Host: "http://pinned.test", CustomIP: "127.0.0.1"}
	result := r.analyze(r.hp, httpx.HTTP, target, http.MethodGet, target.Host, &r.scanopts)
	require.ErrorContains(t, result.Err, "through a proxy")
}

func TestRunner_skipCDNPort_pinned(t *testing.T) {
	r, err := New(&Options{Exclude: []string{"cdn"}})
	require.NoError(t, err)
	defer r.Close()

	// pinned.test does not resolve: only the pinned ip can be classified
	require.True(t, r.skipCDNPort("pinned.test", "151.101.1.1", "8443"), "a CDN ip on another port")
	require.False(t, r.skipCDNPort("pinned.test", "151.101.1.1", "443"), "a CDN ip on 443")
	require.False(t, r.skipCDNPort("pinned.test", "192.0.2.10", "8443"), "an origin ip")
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
	return runPinnedWith(t, &Options{}, lines...)
}

// runPinnedWith is runPinned with options holding the flags under test.
func runPinnedWith(t *testing.T, options *Options, lines ...string) []Result {
	t.Helper()

	var (
		mu      sync.Mutex
		results []Result
	)
	options.Threads = 1
	options.RateLimit = 10
	options.Timeout = 5
	options.Methods = http.MethodGet
	options.Delay = -1
	options.OnResult = func(r Result) {
		if r.Err != nil || r.URL == "" {
			return
		}
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}
	options.InputTargetHost = lines
	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()
	return results
}

// serveTitle serves a page whose title is name and the Host header, and skips
// the test when addr cannot be bound.
func serveTitle(t *testing.T, addr, name string) *httptest.Server {
	t.Helper()
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

// servePair serves "one" on 127.0.0.1 and "two" on 127.0.0.2 with the same
// port, and returns the port and the lines pinning pinned.test to each ip.
func servePair(t *testing.T) (string, []string) {
	t.Helper()
	one := serveTitle(t, "127.0.0.1:0", "one")
	_, port, err := net.SplitHostPort(one.Listener.Addr().String())
	require.NoError(t, err)
	serveTitle(t, net.JoinHostPort("127.0.0.2", port), "two")

	target := "http://pinned.test:" + port
	skipIfProxied(t, target)
	return port, []string{
		fmt.Sprintf(`{"target": %q, "ip": "127.0.0.1"}`, target),
		fmt.Sprintf(`{"target": %q, "ip": "127.0.0.2"}`, target),
	}
}

// serveDNS runs a resolver that answers the A queries for host with ips, and
// returns its address and the number of queries for host it got.
func serveDNS(t *testing.T, host string, ips ...string) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	var queries atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(buf[:n])
			if err != nil {
				continue
			}
			question, err := parser.Question()
			if err != nil {
				continue
			}
			header.Response = true
			builder := dnsmessage.NewBuilder(nil, header)
			_ = builder.StartQuestions()
			_ = builder.Question(question)
			_ = builder.StartAnswers()
			if strings.EqualFold(strings.TrimSuffix(question.Name.String(), "."), host) {
				queries.Add(1)
				for _, ip := range ips {
					if question.Type == dnsmessage.TypeA {
						answer := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
						_ = builder.AResource(answer, dnsmessage.AResource{A: [4]byte(net.ParseIP(ip).To4())})
					}
				}
			}
			if msg, err := builder.Finish(); err == nil {
				_, _ = conn.WriteTo(msg, addr)
			}
		}
	}()
	return conn.LocalAddr().String(), &queries
}

func TestTargetLinePinsTheConnection(t *testing.T) {
	port, lines := servePair(t)
	results := runPinned(t, lines...)

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

// With a matcher, responses are stored after matching, under a name that
// must differ for each ip of a url.
func TestTargetLineStoresTheResponseOfEachIP(t *testing.T) {
	_, lines := servePair(t)
	options := &Options{
		StoreResponse:             true,
		StoreResponseDir:          t.TempDir(),
		MaxResponseBodySizeToSave: math.MaxInt32,
		OutputMatchStatusCode:     "200",
	}
	require.NoError(t, options.ValidateOptions())
	results := runPinnedWith(t, options, lines...)

	require.Len(t, results, 2)
	for _, result := range results {
		data, err := os.ReadFile(result.StoredResponsePath)
		require.NoError(t, err)
		require.Contains(t, string(data), "<title>"+result.Title+"</title>", "the response of %s", result.HostIP)
	}
}

// Like curl --resolve, the host of a pinned target is not resolved: the
// pinned ip is reported in host_ip, and a holds dns data only.
func TestTargetLineIsNotResolved(t *testing.T) {
	_, lines := servePair(t)
	resolver, queries := serveDNS(t, "pinned.test", "127.0.0.2")
	results := runPinnedWith(t, &Options{Resolvers: []string{resolver}}, lines[0])

	require.Len(t, results, 1)
	require.Equal(t, "127.0.0.1", results[0].HostIP)
	require.Empty(t, results[0].A)
	require.Zero(t, queries.Load())
}

// -pa resolves the host, and each of its results keeps all of its addresses.
func TestProbeAllIPsKeepsTheAddressesOfTheHost(t *testing.T) {
	port, _ := servePair(t)
	resolver, _ := serveDNS(t, "pinned.test", "127.0.0.1", "127.0.0.2")
	results := runPinnedWith(t, &Options{Resolvers: []string{resolver}, ProbeAllIPS: true}, "http://pinned.test:"+port)

	require.Len(t, results, 2)
	for _, result := range results {
		require.ElementsMatch(t, []string{"127.0.0.1", "127.0.0.2"}, result.A, "the result of %s", result.HostIP)
	}
}

// An IPv6 ip is dialed as well, which -pa relies on for the IPv6 ips of a host.
func TestTargetLinePinsIPv6(t *testing.T) {
	six := serveTitle(t, "[::1]:0", "six")
	_, port, err := net.SplitHostPort(six.Listener.Addr().String())
	require.NoError(t, err)

	target := "http://pinned.test:" + port
	skipIfProxied(t, target)
	results := runPinned(t, fmt.Sprintf(`{"target": %q, "ip": "::1"}`, target))
	require.Len(t, results, 1)
	require.Equal(t, "::1", results[0].HostIP)
	require.Equal(t, "six pinned.test:"+port, results[0].Title)
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
