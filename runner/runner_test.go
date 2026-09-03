package runner

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/mapcidr/asn"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/stretchr/testify/require"
)

func TestRunner_resumeAfterInterrupt(t *testing.T) {
	domains := []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com", "h.com", "i.com", "j.com"}
	interruptAfter := 4

	// --- Full scan (reference): process all domains without interrupt ---
	rFull, err := New(&Options{})
	require.Nil(t, err, "could not create httpx runner")
	rFull.options.resumeCfg = &ResumeCfg{}
	var fullOutput []string
	for _, d := range domains {
		rFull.options.resumeCfg.current = d
		rFull.options.resumeCfg.currentIndex++
		fullOutput = append(fullOutput, d)
	}

	// --- Interrupted scan: process items, interrupt after interruptAfter ---
	rInt, err := New(&Options{})
	require.Nil(t, err, "could not create httpx runner")
	rInt.options.resumeCfg = &ResumeCfg{}
	var interruptedOutput []string
	for _, d := range domains {
		// same check as processItem: bail out if interrupted
		select {
		case <-rInt.interruptCh:
			continue
		default:
		}

		rInt.options.resumeCfg.current = d
		rInt.options.resumeCfg.currentIndex++
		interruptedOutput = append(interruptedOutput, d)

		if len(interruptedOutput) == interruptAfter {
			rInt.Interrupt()
		}
	}

	// simulate SaveResumeConfig: save the index after interrupt
	savedIndex := rInt.options.resumeCfg.currentIndex

	// the saved index must equal exactly the number of items that were processed
	require.Equal(t, interruptAfter, savedIndex, "resume index should equal number of completed items")
	// every domain before the index must be in the interrupted output
	require.Equal(t, domains[:interruptAfter], interruptedOutput, "interrupted output should contain exactly the first N domains")

	// --- Resumed scan: load saved index, skip already-processed items ---
	rRes, err := New(&Options{})
	require.Nil(t, err, "could not create httpx runner")
	rRes.options.resumeCfg = &ResumeCfg{Index: savedIndex}
	var resumedOutput []string
	for _, d := range domains {
		// same resume-skip logic as processItem
		rRes.options.resumeCfg.current = d
		rRes.options.resumeCfg.currentIndex++
		if rRes.options.resumeCfg.currentIndex <= rRes.options.resumeCfg.Index {
			continue
		}
		resumedOutput = append(resumedOutput, d)
	}

	// every domain after the index must be in the resumed output
	require.Equal(t, domains[interruptAfter:], resumedOutput, "resumed output should contain exactly the remaining domains")

	// union of interrupted + resumed must equal the full scan
	combined := append(interruptedOutput, resumedOutput...)
	require.Equal(t, fullOutput, combined, "interrupted + resumed should equal full scan")
}

func TestRunner_domain_targets(t *testing.T) {
	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := []string{"example.com", "*.example.com", "example.com,one.one.one.one"}
	expected := []httpx.Target{{
		Host: "example.com",
	}, {
		Host: "example.com",
	}, {
		Host:       "one.one.one.one",
		CustomHost: "example.com",
	}}
	got := []httpx.Target{}
	for _, inp := range input {
		for target := range r.targets(r.hp, inp) {
			got = append(got, target)
		}
	}
	require.ElementsMatch(t, expected, got, "could not expected output")
}

func TestRunner_probeall_targets(t *testing.T) {
	options := &Options{
		ProbeAllIPS: true,
	}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := "one.one.one.one"
	expected := []httpx.Target{{
		Host:     "one.one.one.one",
		CustomIP: "2606:4700:4700::1111",
	},
		{
			Host:     "one.one.one.one",
			CustomIP: "2606:4700:4700::1001",
		},
		{
			Host:     "one.one.one.one",
			CustomIP: "1.0.0.1",
		},
		{
			Host:     "one.one.one.one",
			CustomIP: "1.1.1.1",
		}}
	got := []httpx.Target{}
	for target := range r.targets(r.hp, input) {
		got = append(got, target)
	}

	require.ElementsMatch(t, expected, got, "could not expected output")
}

func TestRunner_probeall_targets_with_port(t *testing.T) {
	options := &Options{
		ProbeAllIPS: true,
	}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")

	inputWithPort := "http://one.one.one.one:8080"
	inputWithoutPort := "one.one.one.one"

	gotWithPort := []httpx.Target{}
	for target := range r.targets(r.hp, inputWithPort) {
		gotWithPort = append(gotWithPort, target)
	}

	gotWithoutPort := []httpx.Target{}
	for target := range r.targets(r.hp, inputWithoutPort) {
		gotWithoutPort = append(gotWithoutPort, target)
	}

	require.True(t, len(gotWithPort) > 0, "probe-all-ips with port should return at least one target")
	require.True(t, len(gotWithoutPort) > 0, "probe-all-ips without port should return at least one target")
	require.Equal(t, len(gotWithPort), len(gotWithoutPort), "probe-all-ips should return same number of IPs with or without port")

	for _, target := range gotWithPort {
		require.Equal(t, inputWithPort, target.Host, "Host should be preserved with port")
		require.NotEmpty(t, target.CustomIP, "CustomIP should be populated")
	}
}

func TestRunner_cidr_targets(t *testing.T) {
	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := "173.0.84.0/30"
	expected := []httpx.Target{
		{
			Host: "173.0.84.0",
		}, {
			Host: "173.0.84.1",
		},
		{
			Host: "173.0.84.2",
		},
		{
			Host: "173.0.84.3",
		}}
	got := []httpx.Target{}
	for target := range r.targets(r.hp, input) {
		got = append(got, target)
	}

	require.ElementsMatch(t, expected, got, "could not expected output")
}

func TestRunner_asn_targets(t *testing.T) {
	if os.Getenv("PDCP_API_KEY") == "" {
		return
	}

	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := "AS14421"
	expected := []httpx.Target{}
	expectedOutputFile := "tests/AS14421.txt"
	// read the expected IPs from the file
	fileContent, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err, "could not read the expectedOutputFile file")
	ips := strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")
	for _, ip := range ips {
		expected = append(expected, httpx.Target{Host: ip})
	}

	if _, err := asn.GetIPAddressesAsStream(input); err != nil && stringsutil.ContainsAnyI(err.Error(), "unauthorized: 401") {
		t.Skip("skipping asn test due to missing/invalid api key")
		return
	}

	got := []httpx.Target{}
	for target := range r.targets(r.hp, input) {
		got = append(got, target)
	}
	require.ElementsMatch(t, expected, got, "could not get expected output")
}

func TestRunner_countTargetFromRawTarget(t *testing.T) {
	options := &Options{
		SkipDedupe: false,
	}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")

	input := "example.com"
	expected := 1
	got, err := r.countTargetFromRawTarget(input)
	require.Nil(t, err, "could not count targets")
	require.Equal(t, expected, got, "got wrong output")

	input = "example.com"
	expected = 0
	err = r.hm.Set(input, nil)
	require.Nil(t, err, "could not set value to hm")
	got, err = r.countTargetFromRawTarget(input)
	require.True(t, errors.Is(err, duplicateTargetErr), "expected duplicate target error")
	require.Equal(t, expected, got, "got wrong output")

	input = "173.0.84.0/24"
	expected = 256
	got, err = r.countTargetFromRawTarget(input)
	require.Nil(t, err, "could not count targets")
	require.Equal(t, expected, got, "got wrong output")

	input = ""
	expected = 0
	got, err = r.countTargetFromRawTarget(input)
	require.Nil(t, err, "could not count targets")
	require.Equal(t, expected, got, "got wrong output")

	if os.Getenv("PDCP_API_KEY") != "" {
		input = "AS14421"
		expected = 256
		got, err = r.countTargetFromRawTarget(input)
		if err != nil && stringsutil.ContainsAnyI(err.Error(), "unauthorized: 401") {
			t.Skip("skipping asn test due to missing/invalid api key")
			return
		}
		require.Nil(t, err, "could not count targets")
		require.Equal(t, expected, got, "got wrong output")
	}
}

func TestRunner_urlWithComma_targets(t *testing.T) {
	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := []string{"http://scanme.sh?a=1,2"}
	expected := []httpx.Target{{
		Host: "http://scanme.sh?a=1,2",
	}}
	got := []httpx.Target{}
	for _, inp := range input {
		for target := range r.targets(r.hp, inp) {
			got = append(got, target)
		}
	}
	require.ElementsMatch(t, expected, got, "could not expected output")
}

func TestRunner_CSVRow(t *testing.T) {
	// Create a result with fields that would be vulnerable to CSV injection
	result := Result{
		URL:         `=HYPERLINK('https://evil.com','click me')`,
		Title:       `+CMD('calc')`,
		ContentType: `-SUM(1+1)`,
		WebServer:   `@MACRO=Virus()`,
		StatusCode:  200,
		Timestamp:   time.Now(),
	}

	// Call CSVRow to get the sanitized output
	csvOutput := result.CSVRow(nil)

	// Check that vulnerable fields are properly sanitized with a prefix quote
	tests := []struct {
		fieldName string
		original  string
		expected  string
	}{
		{"URL", result.URL, fmt.Sprintf("'%s", result.URL)},
		{"Title", result.Title, fmt.Sprintf("'%s", result.Title)},
		{"ContentType", result.ContentType, fmt.Sprintf("'%s", result.ContentType)},
		{"WebServer", result.WebServer, fmt.Sprintf("'%s", result.WebServer)},
	}

	for _, tc := range tests {
		if !strings.Contains(csvOutput, tc.expected) {
			t.Errorf("CSV sanitization failed for %s field: expected %q but sanitized value not found in output: %s",
				tc.fieldName, tc.expected, csvOutput)
		}
	}

	// Also check that normal fields remain unsanitized
	if strings.Contains(csvOutput, "'200") {
		t.Error("CSV sanitization incorrectly modified non-vulnerable field")
	}
}

func TestRunner_testAndSet(t *testing.T) {
	r, err := New(&Options{})
	require.Nil(t, err, "could not create httpx runner")

	t.Run("first insert returns true", func(t *testing.T) {
		require.True(t, r.testAndSet("example.com"))
	})

	t.Run("duplicate returns false", func(t *testing.T) {
		require.False(t, r.testAndSet("example.com"))
	})

	t.Run("different key returns true", func(t *testing.T) {
		require.True(t, r.testAndSet("other.com"))
	})

	t.Run("empty string returns false", func(t *testing.T) {
		require.False(t, r.testAndSet(""))
	})

	t.Run("whitespace-only returns false", func(t *testing.T) {
		require.False(t, r.testAndSet("   "))
	})

	t.Run("trimmed duplicate returns false", func(t *testing.T) {
		require.False(t, r.testAndSet("  example.com  "))
	})
}

func TestRunner_testAndSet_concurrent(t *testing.T) {
	r, err := New(&Options{})
	require.Nil(t, err, "could not create httpx runner")

	const goroutines = 100
	key := "race-target.com"
	wins := make([]bool, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			wins[idx] = r.testAndSet(key)
		}(i)
	}

	close(start)
	wg.Wait()

	winCount := 0
	for _, w := range wins {
		if w {
			winCount++
		}
	}
	require.Equal(t, 1, winCount, "exactly one goroutine should win testAndSet for the same key")
}

func TestOptions_hasMatcherOrFilter(t *testing.T) {
	tests := []struct {
		name     string
		options  Options
		expected bool
	}{
		{
			name:     "no matchers or filters",
			options:  Options{},
			expected: false,
		},
		{
			name:     "match status code",
			options:  Options{OutputMatchStatusCode: "200"},
			expected: true,
		},
		{
			name:     "filter status code",
			options:  Options{OutputFilterStatusCode: "403,401"},
			expected: true,
		},
		{
			name:     "match string",
			options:  Options{OutputMatchString: []string{"admin"}},
			expected: true,
		},
		{
			name:     "filter string",
			options:  Options{OutputFilterString: []string{"error"}},
			expected: true,
		},
		{
			name:     "match content length",
			options:  Options{OutputMatchContentLength: "100"},
			expected: true,
		},
		{
			name:     "filter content length",
			options:  Options{OutputFilterContentLength: "0"},
			expected: true,
		},
		{
			name:     "match regex",
			options:  Options{OutputMatchRegex: []string{"admin.*panel"}},
			expected: true,
		},
		{
			name:     "filter regex",
			options:  Options{OutputFilterRegex: []string{"error"}},
			expected: true,
		},
		{
			name:     "match lines count",
			options:  Options{OutputMatchLinesCount: "50"},
			expected: true,
		},
		{
			name:     "filter lines count",
			options:  Options{OutputFilterLinesCount: "0"},
			expected: true,
		},
		{
			name:     "match words count",
			options:  Options{OutputMatchWordsCount: "100"},
			expected: true,
		},
		{
			name:     "filter words count",
			options:  Options{OutputFilterWordsCount: "0"},
			expected: true,
		},
		{
			name:     "match favicon",
			options:  Options{OutputMatchFavicon: []string{"1494302000"}},
			expected: true,
		},
		{
			name:     "filter favicon",
			options:  Options{OutputFilterFavicon: []string{"1494302000"}},
			expected: true,
		},
		{
			name:     "match cdn",
			options:  Options{OutputMatchCdn: []string{"cloudflare"}},
			expected: true,
		},
		{
			name:     "filter cdn",
			options:  Options{OutputFilterCdn: []string{"cloudflare"}},
			expected: true,
		},
		{
			name:     "match condition",
			options:  Options{OutputMatchCondition: "status_code == 200"},
			expected: true,
		},
		{
			name:     "filter condition",
			options:  Options{OutputFilterCondition: "status_code == 403"},
			expected: true,
		},
		{
			name:     "match response time",
			options:  Options{OutputMatchResponseTime: "< 1"},
			expected: true,
		},
		{
			name:     "filter response time",
			options:  Options{OutputFilterResponseTime: "> 5"},
			expected: true,
		},
		{
			name:     "filter page type",
			options:  Options{OutputFilterPageType: []string{"error"}},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.options
			err := opts.ValidateOptions()
			require.Nil(t, err)
			require.Equal(t, tc.expected, opts.HasMatcherOrFilter(),
				"HasMatcherOrFilter() should be %v for %s", tc.expected, tc.name)
		})
	}
}

func TestStoreResponse_withoutMatchersStoresAll(t *testing.T) {
	dir := t.TempDir()
	opts := &Options{
		StoreResponse:    true,
		StoreResponseDir: dir,
	}
	err := opts.ValidateOptions()
	require.Nil(t, err)
	require.False(t, opts.HasMatcherOrFilter())
}

func TestStoreResponse_withMatcherSetsFlag(t *testing.T) {
	dir := t.TempDir()
	opts := &Options{
		StoreResponse:         true,
		StoreResponseDir:      dir,
		OutputMatchStatusCode: "200",
	}
	err := opts.ValidateOptions()
	require.Nil(t, err)
	require.True(t, opts.HasMatcherOrFilter())
}

func TestRunner_duplicate(t *testing.T) {
	const (
		pageA = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Welcome</title></head><body>Hello world default page content here</body></html>"
		pageB = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Dashboard</title></head><body>Completely different application running on this server</body></html>"
	)

	t.Run("same content same IP is duplicate", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		first := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://a.example.com"}
		second := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://b.example.com"}

		require.False(t, r.duplicate(first), "first result should not be duplicate")
		require.True(t, r.duplicate(second), "same content + same IP should be duplicate")
	})

	t.Run("same content different IP is NOT duplicate", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		first := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://a.example.com"}
		second := &Result{Raw: pageA, HostIP: "2.2.2.2", URL: "https://b.example.com"}

		require.False(t, r.duplicate(first))
		require.False(t, r.duplicate(second), "same content but different IP should NOT be duplicate")
	})

	t.Run("different content same IP is NOT duplicate", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		first := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://a.example.com"}
		second := &Result{Raw: pageB, HostIP: "1.1.1.1", URL: "https://b.example.com"}

		require.False(t, r.duplicate(first))
		require.False(t, r.duplicate(second), "different content on same IP should NOT be duplicate")
	})

	t.Run("different content different IP is NOT duplicate", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		first := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://a.example.com"}
		second := &Result{Raw: pageB, HostIP: "2.2.2.2", URL: "https://b.example.com"}

		require.False(t, r.duplicate(first))
		require.False(t, r.duplicate(second), "different content + different IP should NOT be duplicate")
	})

	t.Run("third subdomain same content same IP is duplicate", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		first := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://a.example.com"}
		second := &Result{Raw: pageA, HostIP: "2.2.2.2", URL: "https://b.example.com"}
		third := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://c.example.com"}

		require.False(t, r.duplicate(first))
		require.False(t, r.duplicate(second), "different IP should be kept")
		require.True(t, r.duplicate(third), "same content + same IP as first should be duplicate")
	})

	t.Run("near-duplicate content same IP is duplicate", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		first := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://a.example.com"}
		nearDup := &Result{
			Raw:    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Welcome</title></head><body>Hello world default page content here!</body></html>",
			HostIP: "1.1.1.1",
			URL:    "https://b.example.com",
		}

		require.False(t, r.duplicate(first))
		require.True(t, r.duplicate(nearDup), "near-duplicate content from same IP should be duplicate")
	})

	t.Run("near-duplicate content different IP is NOT duplicate", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		first := &Result{Raw: pageA, HostIP: "1.1.1.1", URL: "https://a.example.com"}
		nearDup := &Result{
			Raw:    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Welcome</title></head><body>Hello world default page content here!</body></html>",
			HostIP: "3.3.3.3",
			URL:    "https://b.example.com",
		}

		require.False(t, r.duplicate(first))
		require.False(t, r.duplicate(nearDup), "near-duplicate content from different IP should NOT be duplicate")
	})

	t.Run("empty IP falls back to content-only dedup", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		first := &Result{Raw: pageA, HostIP: "", URL: "https://a.example.com"}
		second := &Result{Raw: pageA, HostIP: "", URL: "https://b.example.com"}

		require.False(t, r.duplicate(first))
		require.True(t, r.duplicate(second), "empty IP should fall back to content-only dedup")
	})

	t.Run("many subdomains same default page same IP", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		kept := 0
		for i := 0; i < 50; i++ {
			res := &Result{
				Raw:    pageA,
				HostIP: "10.0.0.1",
				URL:    fmt.Sprintf("https://sub%d.example.com", i),
			}
			if !r.duplicate(res) {
				kept++
			}
		}
		require.Equal(t, 1, kept, "50 subdomains with identical content on same IP should keep exactly 1")
	})

	t.Run("many subdomains same default page different IPs", func(t *testing.T) {
		r, err := New(&Options{})
		require.Nil(t, err)

		kept := 0
		for i := 0; i < 50; i++ {
			res := &Result{
				Raw:    pageA,
				HostIP: fmt.Sprintf("10.0.0.%d", i+1),
				URL:    fmt.Sprintf("https://sub%d.example.com", i),
			}
			if !r.duplicate(res) {
				kept++
			}
		}
		require.Equal(t, 50, kept, "50 subdomains with identical content but different IPs should keep all 50")
	})
}

func TestCreateNetworkpolicyInstance_AllowDenyFlags(t *testing.T) {
	runner := &Runner{}

	tests := []struct {
		name      string
		allow     []string
		deny      []string
		testCases []struct {
			ip       string
			expected bool
			reason   string
		}
	}{
		{
			name:  "Allow flag blocks IPs outside allowed range",
			allow: []string{"192.168.1.0/24"},
			deny:  nil,
			testCases: []struct {
				ip       string
				expected bool
				reason   string
			}{
				{"8.8.8.8", false, "IP outside allowed range should be blocked"},
				{"192.168.1.10", true, "IP inside allowed range should be allowed"},
			},
		},
		{
			name:  "Deny flag blocks IPs in denied range",
			allow: nil,
			deny:  []string{"127.0.0.0/8"},
			testCases: []struct {
				ip       string
				expected bool
				reason   string
			}{
				{"127.0.0.1", false, "IP in denied range should be blocked"},
				{"8.8.8.8", true, "IP outside denied range should be allowed"},
			},
		},
		{
			name:  "Combined Allow and Deny flags",
			allow: []string{"192.168.0.0/16"},
			deny:  []string{"192.168.1.0/24"},
			testCases: []struct {
				ip       string
				expected bool
				reason   string
			}{
				{"10.0.0.1", false, "IP outside allowed range should be blocked"},
				{"192.168.1.100", false, "IP in denied range should be blocked even if in allowed range"},
				{"192.168.2.50", true, "IP in allowed range but not in denied range should be allowed"},
			},
		},
		{
			name:  "Multiple Allow and Deny ranges",
			allow: []string{"10.0.0.0/8", "172.16.0.0/12"},
			deny:  []string{"10.1.0.0/16", "172.20.0.0/16"},
			testCases: []struct {
				ip       string
				expected bool
				reason   string
			}{
				{"10.0.1.1", true, "10.0.1.1 should be allowed (in allow range, not in deny)"},
				{"10.1.1.1", false, "10.1.1.1 should be blocked (in deny range)"},
				{"172.16.1.1", true, "172.16.1.1 should be allowed (in allow range, not in deny)"},
				{"172.20.1.1", false, "172.20.1.1 should be blocked (in deny range)"},
				{"192.168.1.1", false, "192.168.1.1 should be blocked (not in any allow range)"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			options := &Options{
				Allow: tc.allow,
				Deny:  tc.deny,
			}

			np, err := runner.createNetworkpolicyInstance(options)
			require.Nil(t, err, "could not create networkpolicy instance")
			require.NotNil(t, np, "networkpolicy instance should not be nil")

			for _, testCase := range tc.testCases {
				allowed := np.Validate(testCase.ip)
				require.Equal(t, testCase.expected, allowed, testCase.reason)
			}
		})
	}
}

// startTLSOnlyListener serves content over TLS and answers any plaintext
// request the way a real TLS listener does: a valid HTTP 400 saying TLS is
// required. The response is a successful HTTP transaction, which is what stops
// the transport-error scheme retry from firing.
func startTLSOnlyListener(t *testing.T) string {
	t.Helper()

	const rejection = "HTTP/1.1 400 Bad Request\r\n" +
		"Connection: close\r\n" +
		"Content-Type: text/plain;charset=utf-8\r\n" +
		"Content-Length: 62\r\n\r\n" +
		"Bad Request\r\nThis combination of host and port requires TLS.\r\n"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls-only.test"},
		DNSNames:     []string{"localhost", "tls-only.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><head><title>Only Over TLS</title></head><body>ok</body></html>")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				buffered := bufio.NewReader(conn)
				first, err := buffered.Peek(1)
				if err != nil {
					_ = conn.Close()
					return
				}
				// 0x16 is a TLS handshake record; anything else is plaintext.
				if first[0] != 0x16 {
					drainRequest(buffered)
					_, _ = io.WriteString(conn, rejection)
					_ = conn.Close()
					return
				}
				// Always returns io.EOF: the listener yields this one connection.
				_ = server.Serve(oneShot(tls.Server(&peeked{Conn: conn, reader: buffered}, tlsConfig)))
			}(conn)
		}
	}()

	return listener.Addr().String()
}

// drainRequest reads the request head before a reply is written. Answering an
// HTTP client that has not finished asking is an unsolicited response, and it
// discards the reply instead of parsing it.
func drainRequest(r io.Reader) {
	if conn, ok := r.(net.Conn); ok {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if scanner.Text() == "" {
			return
		}
	}
}

type peeked struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peeked) Read(b []byte) (int, error) { return c.reader.Read(b) }

type oneShotListener struct {
	conn net.Conn
	used bool
}

func oneShot(conn net.Conn) net.Listener { return &oneShotListener{conn: conn} }

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, io.EOF
	}
	l.used = true
	return l.conn, nil
}
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// TestTLSOnlyPortIsProbedOverHTTPS covers a TLS-only service on a port above
// 1024, which the scheme heuristic probes as plain HTTP first. Without the
// retry on a TLS-required response the service is reported as plain http.
func TestTLSOnlyPortIsProbedOverHTTPS(t *testing.T) {
	target := startTLSOnlyListener(t)

	var (
		mu      sync.Mutex
		results []Result
	)

	options := &Options{
		Threads:   1,
		RateLimit: 10,
		Retries:   0,
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
		InputTargetHost: []string{target},
	}

	// The heuristic must pick http first, otherwise this test proves nothing.
	require.Equal(t, "http", determineMostLikelySchemeOrder(target))

	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, results, 1)
	require.Equal(t, "https", results[0].Scheme)
	require.Equal(t, "https://"+target, results[0].URL)
	require.Equal(t, http.StatusOK, results[0].StatusCode)
}

// TestPlainHTTPPortStaysHTTP is the no-regression half of the TLS upgrade: a
// genuine cleartext service that answers 400 must not be relabelled https just
// because the upgrade was attempted.
func TestPlainHTTPPortStaysHTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				drainRequest(conn)
				_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"+
					"Content-Type: text/plain\r\nContent-Length: 11\r\n\r\nBad Request")
				_ = conn.Close()
			}(conn)
		}
	}()

	target := listener.Addr().String()

	var (
		mu      sync.Mutex
		results []Result
	)
	options := &Options{
		Threads:   1,
		RateLimit: 10,
		Retries:   0,
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
		InputTargetHost: []string{target},
	}

	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, results, 1)
	require.Equal(t, "http", results[0].Scheme, "a cleartext 400 must stay http")
	require.Equal(t, http.StatusBadRequest, results[0].StatusCode)
}

// TestOneShotPlainHTTPKeepsItsResult covers a cleartext service that answers
// once and then refuses: the scheme decision must not cost it a second
// request, or a reachable service disappears from the output.
func TestOneShotPlainHTTPKeepsItsResult(t *testing.T) {
	var served int64

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if atomic.AddInt64(&served, 1) != 1 {
					return // refuse every later connection
				}
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				drainRequest(conn)
				_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"+
					"Content-Length: 11\r\n\r\nBad Request")
			}(conn)
		}
	}()

	var (
		mu      sync.Mutex
		results []Result
	)
	options := &Options{
		Threads: 1, RateLimit: 10, Retries: 0, Timeout: 5,
		Methods: http.MethodGet, Delay: -1,
		InputTargetHost: []string{listener.Addr().String()},
		OnResult: func(r Result) {
			if r.Err != nil || r.URL == "" {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
	}

	runner, err := New(options)
	require.NoError(t, err)
	defer runner.Close()
	runner.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, results, 1, "a service that answered once must still be reported")
	require.Equal(t, "http", results[0].Scheme)
	require.Equal(t, http.StatusBadRequest, results[0].StatusCode)
}

// TestHandshakeThenCloseKeepsPlainResult covers a port whose TLS handshake
// succeeds and which then closes without answering: the upgrade must fall back
// to the plaintext response rather than request it again, so a cleartext
// service that answers only once still appears in the output.
func TestHandshakeThenCloseKeepsPlainResult(t *testing.T) {
	var plainServed, h2cServed, tlsHandshakes int64

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "handshake.test"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				buffered := bufio.NewReader(conn)
				first, err := buffered.Peek(1)
				if err != nil {
					return
				}
				// 0x16 is a TLS ClientHello: complete the handshake, then close
				// without ever sending an HTTP response.
				if first[0] == 0x16 {
					tlsConn := tls.Server(&peeked{Conn: conn, reader: buffered}, tlsConfig)
					if err := tlsConn.HandshakeContext(context.Background()); err != nil {
						return
					}
					atomic.AddInt64(&tlsHandshakes, 1)
					_ = tlsConn.Close()
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				request, err := http.ReadRequest(buffered)
				if err != nil {
					return
				}
				_ = request.Body.Close()
				if strings.EqualFold(request.Header.Get("Upgrade"), "h2c") {
					atomic.AddInt64(&h2cServed, 1)
					_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
						"Connection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
					return
				}
				if atomic.AddInt64(&plainServed, 1) != 1 {
					return // the cleartext application answers exactly once
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"+
					"Content-Length: 11\r\n\r\nBad Request")
			}(conn)
		}
	}()

	var (
		mu      sync.Mutex
		results []Result
	)
	options := &Options{
		Threads: 1, RateLimit: 10, Retries: 0, Timeout: 5,
		Methods: http.MethodGet, Delay: -1,
		HTTP2Probe:      true,
		InputTargetHost: []string{listener.Addr().String()},
		OnResult: func(r Result) {
			if r.Err != nil || r.URL == "" {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
	}

	runner, err := New(options)
	require.NoError(t, err)
	defer runner.Close()
	runner.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, results, 1, "the plaintext result must survive a failed HTTPS attempt")
	require.Equal(t, "http", results[0].Scheme)
	require.Equal(t, http.StatusBadRequest, results[0].StatusCode)
	require.True(t, results[0].HTTP2,
		"the h2c probe must use the restored plaintext URL")
	require.EqualValues(t, 1, atomic.LoadInt64(&plainServed),
		"the plaintext service must not be asked a second time")
	require.EqualValues(t, 1, atomic.LoadInt64(&h2cServed),
		"exactly one plaintext HTTP/2 probe must be observed")
	require.EqualValues(t, 1, atomic.LoadInt64(&tlsHandshakes),
		"the failed HTTPS request must complete its TLS handshake first")
}
