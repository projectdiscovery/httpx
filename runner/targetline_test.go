package runner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/httpx/common/httpx"
	syncutil "github.com/projectdiscovery/utils/sync"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestParseTargetLine(t *testing.T) {
	valid := map[string]struct {
		line string
		want targetLine
	}{
		"ipv4":           {`{"target": "https://a.example", "ip": "192.0.2.10"}`, targetLine{Target: "https://a.example", IP: "192.0.2.10"}},
		"ipv6":           {`{"target": " a.example:8443 ", "ip": "2001:DB8::1"}`, targetLine{Target: "a.example:8443", IP: "2001:db8::1"}},
		"ipv4-mapped":    {`{"target": "a.example", "ip": "::ffff:192.0.2.10"}`, targetLine{Target: "a.example", IP: "192.0.2.10"}},
		"spaced ip":      {`{"target": "a.example", "ip": " 192.0.2.10 "}`, targetLine{Target: "a.example", IP: "192.0.2.10"}},
		"no ip":          {`{"target": "a.example"}`, targetLine{Target: "a.example"}},
		"escaped target": {`{"target": "https://a.example/?a=1&b=2"}`, targetLine{Target: "https://a.example/?a=1&b=2"}},
		"nuclei keys":    {`{"target": "a.example", "ip": "192.0.2.10", "tags": ["cve"], "severity": "high"}`, targetLine{Target: "a.example", IP: "192.0.2.10"}},
	}
	for name, tc := range valid {
		t.Run(name, func(t *testing.T) {
			got, err := parseTargetLine(tc.line)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	invalid := map[string]struct{ line, reason string }{
		"malformed json": {`{"target": "a.example"`, "unexpected EOF"},
		"trailing data":  {`{"target": "a.example"} x`, "unexpected data after the object"},
		"unknown key":    {`{"target": "a.example", "ips": "192.0.2.10"}`, "unknown keys ips"},
		"key case":       {`{"target": "a.example", "IP": "192.0.2.10"}`, "unknown keys IP"},
		"missing target": {`{"ip": "192.0.2.10"}`, "no target"},
		"invalid ip":     {`{"target": "a.example", "ip": "192.0.2"}`, `invalid ip "192.0.2"`},
		"null ip":        {`{"target": "a.example", "ip": null}`, `invalid ip ""`},
		"empty ip":       {`{"target": "a.example", "ip": ""}`, `invalid ip ""`},
		"number ip":      {`{"target": "a.example", "ip": 1}`, "cannot unmarshal number"},
		"ip with zone":   {`{"target": "a.example", "ip": "fe80::1%eth0"}`, "invalid ip"},
		"unspecified ip": {`{"target": "a.example", "ip": "0.0.0.0"}`, "invalid ip"},
		"ip target":      {`{"target": "https://192.0.2.1", "ip": "192.0.2.10"}`, "must have a hostname"},
		"cidr target":    {`{"target": "192.0.2.0/24", "ip": "192.0.2.10"}`, "CIDR or ASN"},
		"asn target":     {`{"target": "AS13335", "ip": "192.0.2.10"}`, "CIDR or ASN"},
		"wildcard":       {`{"target": "*.a.example", "ip": "192.0.2.10"}`, "wildcard"},
		"vhost form":     {`{"target": "a.example,192.0.2.1", "ip": "192.0.2.10"}`, "vhost,ip"},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := parseTargetLine(tc.line)
			require.ErrorContains(t, err, tc.reason)
		})
	}
}

func TestRunner_parseInput(t *testing.T) {
	r := &Runner{options: &Options{}}

	t.Run("equivalent lines are stored once", func(t *testing.T) {
		for _, line := range []string{
			`{"target": "https://a.example", "ip": "192.0.2.10"}`,
			` {"ip":"::ffff:192.0.2.10","target":"https://a.example"}`,
		} {
			parsed, err := r.parseInput(line)
			require.NoError(t, err)
			require.Equal(t, `{"target":"https://a.example","ip":"192.0.2.10"}`, parsed.key())
		}
	})
	t.Run("a line without ip is the plain target", func(t *testing.T) {
		parsed, err := r.parseInput(`{"target": "https://a.example"}`)
		require.NoError(t, err)
		require.Equal(t, targetLine{Target: "https://a.example"}, parsed)
		require.Equal(t, "https://a.example", parsed.key())
	})
	t.Run("an invalid line is named", func(t *testing.T) {
		_, err := r.parseInput(`{"target": "https://a.example", "ip": "192.0.2"}`)
		require.ErrorContains(t, err, `invalid target line "{\"target\"`)
	})
}

func TestRunner_targetLineConflicts(t *testing.T) {
	conflicts := map[string]Options{
		"-unsafe":      {Unsafe: true},
		"-pipeline":    {Pipeline: true},
		"-http2":       {HTTP2Probe: true},
		"-pr http2":    {Protocol: "HTTP2"},
		"-jarm":        {Jarm: true},
		"-screenshot":  {Screenshot: true},
		"-vhost-input": {VHostInput: true},
		"-proxy":       {Proxy: "http://127.0.0.1:8080"},
	}
	for flag, options := range conflicts {
		t.Run(flag, func(t *testing.T) {
			r := &Runner{options: &options}
			_, err := r.parseInput(`{"target": "https://a.example", "ip": "192.0.2.10"}`)
			require.ErrorIs(t, err, errTargetLineConflict)
			require.ErrorContains(t, err, "keep to its ip: "+flag)
			_, err = r.parseInput(`{"target": "https://a.example"}`)
			require.NoError(t, err, "only a line with an ip conflicts")
		})
	}
}

func TestRunner_New_probeAllIPsWithProxy(t *testing.T) {
	for _, options := range []*Options{
		{ProbeAllIPS: true, Proxy: "http://127.0.0.1:8080"},
		{ProbeAllIPS: true, HTTPProxy: "http://127.0.0.1:8080"},
	} {
		_, err := New(options)
		require.ErrorContains(t, err, "-pa/-probe-all-ips cannot be used with -proxy")
	}
}

// A line given to Process is read as an input line is.
func TestRunner_Process_readsTheLine(t *testing.T) {
	port := serveLocal(t, titleHandler("one"))
	resolver, _ := serveDNS(t, "pinned.test", "127.0.0.1")
	process := func(t *testing.T, options *Options, line string) []Result {
		options.Timeout = 5
		options.Methods = http.MethodGet
		options.Resolvers = []string{resolver}
		require.NoError(t, options.ValidateOptions())
		r, err := New(options)
		require.NoError(t, err)
		defer r.Close()
		wg, err := syncutil.New(syncutil.WithSize(1))
		require.NoError(t, err)

		output := make(chan Result, 1)
		r.Process(line, wg, httpx.HTTP, &r.scanopts, output)
		wg.Wait()
		close(output)
		var results []Result
		for result := range output {
			results = append(results, result)
		}
		return results
	}

	t.Run("a line without ip is the plain target", func(t *testing.T) {
		results := process(t, &Options{}, `{"target": "http://pinned.test:`+port+`"}`)
		require.Len(t, results, 1)
		require.Equal(t, "http://pinned.test:"+port, results[0].Input)
		require.Equal(t, []string{"127.0.0.1"}, results[0].A, "its host is resolved")
	})
	t.Run("an invalid line is reported and skipped", func(t *testing.T) {
		logged := recordErrors(t)
		require.Empty(t, process(t, &Options{}, `{"target": "http://pinned.test:`+port+`", "ip": null}`))
		require.Len(t, logged.containing("Skipping input"), 1)
	})
}

// An invalid line, such as a line of another tool's JSON output, is reported
// and skipped, and the other lines are read, before probing or, with -stream,
// while probing.
func TestRunner_skipsInvalidLines(t *testing.T) {
	file := filepath.Join(t.TempDir(), "targets.txt")
	lines := "a.example\n" +
		`{"host": "b.example"}` + "\n" +
		`{"target": "c.example", "ip": null}` + "\n" +
		`{"target": "d.example", "ip": "192.0.2.10"}` + "\n"
	require.NoError(t, os.WriteFile(file, []byte(lines), 0o600))
	want := []string{"a.example", `{"target":"d.example","ip":"192.0.2.10"}`}

	t.Run("-l", func(t *testing.T) {
		logged := recordErrors(t)
		r, err := New(&Options{})
		require.NoError(t, err)
		defer r.Close()
		input, err := os.Open(file)
		require.NoError(t, err)

		count, err := r.loadAndCloseFile(input)
		require.NoError(t, err)
		require.Equal(t, len(want), count)
		for _, key := range want {
			_, ok := r.hm.Get(key)
			require.True(t, ok, key)
		}
		require.Len(t, logged.containing("Skipping input"), 2, "each skipped line is reported")
	})
	t.Run("-stream", func(t *testing.T) {
		r, err := New(&Options{Stream: true, InputFile: file})
		require.NoError(t, err)
		defer r.Close()
		out, err := r.streamInput()
		require.NoError(t, err)

		var got []string
		for item := range out {
			got = append(got, item)
		}
		require.Equal(t, want, got)
	})
}

func TestRunner_skip_pinned(t *testing.T) {
	r, err := New(&Options{Exclude: []string{"cdn"}})
	require.NoError(t, err)
	defer r.Close()
	URL, err := r.parseURL("http://pinned.test:8443")
	require.NoError(t, err)

	// pinned.test does not resolve: only the pinned ip can be checked
	skip, result := r.skip(URL, httpx.Target{Host: "http://pinned.test:8443", CustomIP: "151.101.1.1"}, "")
	require.True(t, skip)
	require.ErrorContains(t, result.Err, "cdn target")

	skip, _ = r.skip(URL, httpx.Target{Host: "http://pinned.test:8443", CustomIP: "192.0.2.11"}, "")
	require.False(t, skip)
}

// A proxy resolves the host itself, so a probe of a pinned target through it
// fails, which is reported once. Only the proxy of the environment can be
// used with pinned targets, but it is read once per process: the proxy of the
// options stands for it here, and common/httpx tests it.
func TestRunner_analyze_pinnedThroughProxy(t *testing.T) {
	logged := recordErrors(t)
	r, err := New(&Options{Proxy: "http://127.0.0.1:1", HostMaxErrors: -1})
	require.NoError(t, err)
	defer r.Close()

	for range 2 {
		result := analyzeHTTP(r, httpx.Target{Host: "http://pinned.test", CustomIP: "127.0.0.1"})
		require.ErrorIs(t, result.Err, httpx.ErrPinnedThroughProxy)
	}
	require.Len(t, logged.containing("NO_PROXY"), 1)
}

// A name of a certificate shaped like a target line is probed with -tls-probe
// as a plain name: the server being probed cannot pin a target to an ip.
func TestRunner_probeTLSNames_cannotPin(t *testing.T) {
	var requests atomic.Int32
	// the names are probed over the scheme of the target they come from
	pinned := serve(t, listen(t, "127.0.0.1:0"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}), &tls.Config{})
	certificate := selfSignedCertificate(t, pinnedLine("https://pinned.test:"+portOf(t, pinned.Listener), "127.0.0.1"))
	server := serve(t, listen(t, "127.0.0.1:0"), titleHandler("tls"), &tls.Config{Certificates: []tls.Certificate{certificate}})

	results := probe(t, &Options{TLSProbe: true, TLSGrab: true, Threads: 5}, server.URL)
	require.NotEmpty(t, results)
	require.Zero(t, requests.Load())
}

// -maxhr counts the failures of each ip of a host apart, and -probe shows the
// ip that failed.
func TestRunner_analyze_hostErrorsPerIP(t *testing.T) {
	port := serveLocal(t, titleHandler("one"))
	r, err := New(&Options{HostMaxErrors: 1, Timeout: 2, Probe: true})
	require.NoError(t, err)
	defer r.Close()
	target := func(ip string) httpx.Target {
		return httpx.Target{Host: "http://pinned.test:" + port, CustomIP: ip}
	}

	failed := analyzeHTTP(r, target("127.0.0.3"))
	require.Error(t, failed.Err, "nothing listens there")
	require.Contains(t, failed.str, "[127.0.0.3]")
	require.Equal(t, "127.0.0.3", failed.HostIP)
	require.ErrorContains(t, analyzeHTTP(r, target("127.0.0.3")).Err, "previously unresponsive")
	require.NoError(t, analyzeHTTP(r, target("127.0.0.1")).Err, "the other ip of the host is not skipped")
}

// The key of a pinned target differs from the key of any target that is not,
// whose url may hold an "@".
func TestPinnedKey(t *testing.T) {
	require.Equal(t, "GET:http://a.example/x", pinnedKey("GET:http://a.example/x", ""))
	require.NotEqual(t, pinnedKey("GET:http://a.example/x@192.0.2.1", ""), pinnedKey("GET:http://a.example/x", "192.0.2.1"))
}

// Lines pinning a host to two ips reach the server on each, once for
// equivalent lines, with the ip in the output and the canonical line as input.
func TestTargetLinePinsTheConnection(t *testing.T) {
	port := servePair(t, titleHandler("one"), titleHandler("two"))
	target := "http://pinned.test:" + port
	lines := append(pinnedLines(port, "127.0.0.1", "127.0.0.2"), fmt.Sprintf(` {"ip": "::ffff:127.0.0.1", "target": %q}`, target))
	results := probe(t, &Options{}, lines...)

	var got []string
	for _, result := range results {
		got = append(got, result.HostIP+" "+result.Title)
		require.Contains(t, result.str, "["+result.HostIP+"]", "the output shows the ip")
		require.Equal(t, fmt.Sprintf(`{"target":%q,"ip":%q}`, target, result.HostIP), result.Input)
	}
	sort.Strings(got)
	require.Equal(t, []string{
		"127.0.0.1 one pinned.test:" + port,
		"127.0.0.2 two pinned.test:" + port,
	}, got)
}

// The scheme of the target of a line is kept, as for a url given as is.
func TestTargetLineKeepsTheScheme(t *testing.T) {
	port := serveLocal(t, titleHandler("one"))
	require.Len(t, probe(t, &Options{}, pinnedLine("http://pinned.test:"+port, "127.0.0.1")), 1)
	require.Empty(t, probe(t, &Options{}, pinnedLine("https://pinned.test:"+port, "127.0.0.1")), "a plain http server does not answer https")
}

// A redirect to the pinned host goes to the ip, on any port, and a redirect to
// another host does not.
func TestTargetLineRedirects(t *testing.T) {
	other := servePair(t, titleHandler("one"), titleHandler("two"))
	for _, tc := range []struct{ name, location, want string }{
		{"to the pinned host", "http://pinned.test:" + other + "/", "two pinned.test:" + other},
		{"to another host", "http://127.0.0.1:" + other + "/", "one 127.0.0.1:" + other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := servePair(t, titleHandler("one"), http.RedirectHandler(tc.location, http.StatusFound))
			results := probe(t, &Options{FollowRedirects: true, MaxRedirects: 10}, pinnedLines(port, "127.0.0.2")...)

			require.Len(t, results, 1)
			require.Equal(t, tc.want, results[0].Title)
		})
	}
}

// An ip excluded with -e is not connected to, as the dialer keeps to the
// network policy.
func TestTargetLineKeepsToTheExclusions(t *testing.T) {
	var requests atomic.Int32
	port := serveLocal(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	require.Empty(t, probe(t, &Options{Exclude: []string{"127.0.0.1"}}, pinnedLines(port, "127.0.0.1")...))
	require.Zero(t, requests.Load())
}

// With a matcher, responses are stored after matching, under a name that
// must differ for each ip of a url.
func TestTargetLineStoresTheResponseOfEachIP(t *testing.T) {
	port := servePair(t, titleHandler("one"), titleHandler("two"))
	options := &Options{StoreResponse: true, StoreResponseDir: t.TempDir(), OutputMatchStatusCode: "200"}
	results := probe(t, options, pinnedLines(port, "127.0.0.1", "127.0.0.2")...)

	require.Len(t, results, 2)
	for _, result := range results {
		data, err := os.ReadFile(result.StoredResponsePath)
		require.NoError(t, err)
		require.Contains(t, string(data), "<title>"+result.Title+"</title>", "the response of %s", result.HostIP)
	}
}

// Like curl --resolve, the host of a pinned target is not resolved, with -pa
// too, so its result has no A records.
func TestTargetLineIsNotResolved(t *testing.T) {
	port := serveLocal(t, titleHandler("one"))
	for _, probeAllIPs := range []bool{false, true} {
		t.Run(fmt.Sprint("-pa ", probeAllIPs), func(t *testing.T) {
			resolver, queries := serveDNS(t, "pinned.test", "127.0.0.2")
			results := probe(t, &Options{Resolvers: []string{resolver}, ProbeAllIPS: probeAllIPs}, pinnedLines(port, "127.0.0.1")...)

			require.Len(t, results, 1)
			require.Equal(t, "one pinned.test:"+port, results[0].Title)
			require.Empty(t, results[0].A)
			require.Zero(t, queries.Load())
		})
	}
}

// -pa resolves the host, and each of its results keeps all of its addresses.
func TestProbeAllIPsKeepsTheAddressesOfTheHost(t *testing.T) {
	port := servePair(t, titleHandler("one"), titleHandler("two"))
	resolver, _ := serveDNS(t, "pinned.test", "127.0.0.1", "127.0.0.2")
	results := probe(t, &Options{Resolvers: []string{resolver}, ProbeAllIPS: true}, "http://pinned.test:"+port)

	require.Len(t, results, 2)
	for _, result := range results {
		require.ElementsMatch(t, []string{"127.0.0.1", "127.0.0.2"}, result.A, "the result of %s", result.HostIP)
	}
}

// A plain target reports the ip it was dialed to, not the one a pinned target
// of the same host was dialed to meanwhile.
func TestPlainTargetReportsItsOwnIP(t *testing.T) {
	pinnedDialed := make(chan struct{})
	var once sync.Once
	one := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(pinnedDialed) })
		titleHandler("one").ServeHTTP(w, r)
	})
	// the plain target is answered once the pinned target is dialed
	two := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-pinnedDialed:
			titleHandler("two").ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	})
	port := servePair(t, one, two)
	resolver, _ := serveDNS(t, "pinned.test", "127.0.0.2")
	file := filepath.Join(t.TempDir(), "targets.txt")
	lines := "http://pinned.test:" + port + "\n" + pinnedLines(port, "127.0.0.1")[0] + "\n"
	require.NoError(t, os.WriteFile(file, []byte(lines), 0o600))

	// the delay dials the plain target first
	options := &Options{Resolvers: []string{resolver}, Stream: true, InputFile: file, Threads: 2, Delay: 100 * time.Millisecond}
	var got []string
	for _, result := range probe(t, options) {
		got = append(got, result.HostIP+" "+result.Title)
	}
	sort.Strings(got)
	require.Equal(t, []string{
		"127.0.0.1 one pinned.test:" + port,
		"127.0.0.2 two pinned.test:" + port,
	}, got)
}

// An IPv6 ip is dialed as well, which -pa relies on for the IPv6 ips of a host.
func TestTargetLinePinsIPv6(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 is not available: %v", err)
	}
	port := portOf(t, serve(t, listener, titleHandler("six"), nil).Listener)
	results := probe(t, &Options{}, pinnedLines(port, "::1")...)

	require.Len(t, results, 1)
	require.Equal(t, "six pinned.test:"+port, results[0].Title)
}

func TestTargetLineKeepsSNI(t *testing.T) {
	var (
		mu    sync.Mutex
		names []string
	)
	server := serve(t, listen(t, "127.0.0.1:0"), titleHandler("tls"), &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			names = append(names, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	})
	results := probe(t, &Options{}, pinnedLine("https://pinned.test:"+portOf(t, server.Listener), "127.0.0.1"))

	require.Len(t, results, 1)
	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, names)
	for _, name := range names {
		require.Equal(t, "pinned.test", name)
	}
}

// The favicon request and the ztls handshake of -tls-grab connect through the
// pinned ip as well.
func TestTargetLinePinsTheFaviconAndTLSGrab(t *testing.T) {
	server := serve(t, listen(t, "127.0.0.1:0"), withFavicon(titleHandler("tls")), &tls.Config{})
	options := &Options{Favicon: true, ZTLS: true, TLSGrab: true}
	results := probe(t, options, pinnedLine("https://pinned.test:"+portOf(t, server.Listener), "127.0.0.1"))

	require.Len(t, results, 1)
	require.NotEmpty(t, results[0].FavIconMMH3)
	require.NotNil(t, results[0].TLSData)
}

// The favicon request does not take the trace of the probe, whose -trace
// result would then describe the favicon request.
func TestRunner_HandleFaviconHash_keepsTheTraceOfTheProbe(t *testing.T) {
	favicon := serve(t, listen(t, "127.0.0.1:0"), withFavicon(titleHandler("favicon")), nil)
	page := serve(t, listen(t, "127.0.0.1:0"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `<html><head><link rel="icon" href="%s/favicon.ico"></head></html>`, favicon.URL)
	}), nil)
	r, err := New(&Options{Timeout: 5, Methods: http.MethodGet, Trace: true, Favicon: true, MaxResponseBodySizeToRead: int(httpx.DefaultMaxResponseBodySize)})
	require.NoError(t, err)
	defer r.Close()

	result := analyzeHTTP(r, httpx.Target{Host: page.URL})
	require.NoError(t, result.Err)
	require.NotEmpty(t, result.FavIconMMH3)
	require.Equal(t, page.Listener.Addr().String(), fmt.Sprint(result.Trace.GetConn.Info))
}

// errorRecorder is a gologger writer that keeps the errors, which are shown
// by default.
type errorRecorder struct {
	mu     sync.Mutex
	errors []string
}

func (w *errorRecorder) Write(data []byte, level levels.Level) {
	if level == levels.LevelError {
		w.mu.Lock()
		w.errors = append(w.errors, string(data))
		w.mu.Unlock()
	}
}

// recordErrors records the errors logged until the end of the test.
func recordErrors(t *testing.T) *errorRecorder {
	t.Helper()
	logged := &errorRecorder{}
	gologger.DefaultLogger.SetWriter(logged)
	t.Cleanup(func() { gologger.DefaultLogger.SetWriter(writer.NewCLI()) })
	return logged
}

// containing returns the errors that contain text.
func (w *errorRecorder) containing(text string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var lines []string
	for _, line := range w.errors {
		if strings.Contains(line, text) {
			lines = append(lines, line)
		}
	}
	return lines
}

// selfSignedCertificate returns a certificate whose common name is name.
func selfSignedCertificate(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// titleHandler serves a page whose title is name and the Host header.
func titleHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "<title>%s %s</title>", name, r.Host)
	})
}

// withFavicon serves a PNG image as /favicon.ico, and the rest with handler.
func withFavicon(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			_, _ = w.Write([]byte("\x89PNG\r\n\x1a\n"))
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func listen(t *testing.T, addr string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	return listener
}

// serve serves handler on listener, over TLS if tlsConfig is set.
func serve(t *testing.T, listener net.Listener, handler http.Handler, tlsConfig *tls.Config) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	_ = server.Listener.Close()
	server.Listener = listener
	if tlsConfig != nil {
		server.TLS = tlsConfig
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

// serveLocal serves handler on 127.0.0.1, and returns the port.
func serveLocal(t *testing.T, handler http.Handler) string {
	t.Helper()
	return portOf(t, serve(t, listen(t, "127.0.0.1:0"), handler, nil).Listener)
}

func portOf(t *testing.T, listener net.Listener) string {
	t.Helper()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	return port
}

// servePair serves one on 127.0.0.1 and two on 127.0.0.2 with the same port,
// and returns the port. It skips the test where 127.0.0.2 cannot be bound, as
// on macOS.
func servePair(t *testing.T, one, two http.Handler) string {
	t.Helper()
	var err error
	for range 5 {
		first := listen(t, "127.0.0.1:0")
		port := portOf(t, first)
		var second net.Listener
		if second, err = net.Listen("tcp", net.JoinHostPort("127.0.0.2", port)); err == nil {
			serve(t, first, one, nil)
			serve(t, second, two, nil)
			return port
		}
		// the port may be taken on 127.0.0.2: try another one
		_ = first.Close()
	}
	t.Skipf("cannot listen on 127.0.0.2: %v", err)
	return ""
}

func pinnedLine(target, ip string) string {
	return fmt.Sprintf(`{"target": %q, "ip": %q}`, target, ip)
}

// pinnedLines returns the lines pinning http://pinned.test:port to each ip.
func pinnedLines(port string, ips ...string) []string {
	var lines []string
	for _, ip := range ips {
		lines = append(lines, pinnedLine("http://pinned.test:"+port, ip))
	}
	return lines
}

// serveDNS runs a resolver that answers the A queries for host with ips, and
// returns its address and the number of queries for host it got.
func serveDNS(t *testing.T, host string, ips ...string) (string, *atomic.Int32) {
	t.Helper()
	var records []dnsmessage.AResource
	for _, ip := range ips {
		addr := netip.MustParseAddr(ip)
		require.True(t, addr.Is4(), ip)
		records = append(records, dnsmessage.AResource{A: addr.As4()})
	}
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
				if question.Type == dnsmessage.TypeA {
					answer := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
					for _, record := range records {
						_ = builder.AResource(answer, record)
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

// analyzeHTTP probes target over http with r.
func analyzeHTTP(r *Runner, target httpx.Target) Result {
	return r.analyze(r.hp, httpx.HTTP, target, http.MethodGet, targetLine{Target: target.Host, IP: target.CustomIP}, &r.scanopts)
}

// probe runs a runner on inputs with options, completed with test defaults,
// and returns its results. The results that failed are logged.
func probe(t *testing.T, options *Options, inputs ...string) []Result {
	t.Helper()
	if options.Threads == 0 {
		options.Threads = 1
	}
	if options.Timeout == 0 {
		options.Timeout = 5
	}
	if options.MaxResponseBodySizeToRead == 0 {
		options.MaxResponseBodySizeToRead = int(httpx.DefaultMaxResponseBodySize)
		options.MaxResponseBodySizeToSave = int(httpx.DefaultMaxResponseBodySize)
	}
	options.Methods = http.MethodGet
	options.InputTargetHost = inputs
	require.NoError(t, options.ValidateOptions())

	var (
		mu      sync.Mutex
		results []Result
	)
	options.OnResult = func(result Result) {
		if result.Err != nil || result.URL == "" {
			t.Logf("%s: %v", result.Input, result.Err)
			return
		}
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	}
	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()
	return results
}
