package runner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/mapcidr/asn"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
	"github.com/stretchr/testify/require"
)

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
	options := &Options{}
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
	require.Nil(t, err, "could not count targets")
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

func TestRunner_Process_And_RetryLoop(t *testing.T) {
	var hits1, hits2 int32
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits1, 1) != 4 {
			log.Println("serv1 429")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		log.Println("serv1 200")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits2, 1) != 3 {
			log.Println("serv2 429")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		log.Println("serv2 200")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	r, err := New(&Options{
		Threads:     1,
		Delay:       0,
		RetryRounds: 3,
		RetryDelay:  200, // Duration 권장
		Timeout:     2,
	})
	require.NoError(t, err)

	output := make(chan Result)
	retryCh := make(chan retryJob)

	// ctx, timeout := context.WithTimeout(context.Background(), time.Duration(r.options.Timeout))
	// defer timeout()
	cancel, wait := r.retryLoop(context.Background(), retryCh, output, r.analyze)

	wg, _ := syncutil.New(syncutil.WithSize(r.options.Threads))
	so := r.scanopts.Clone()
	so.Methods = []string{"GET"}
	so.TLSProbe = false
	so.CSPProbe = false

	seed := map[string]string{
		"srv1": srv1.URL,
		"srv2": srv2.URL,
	}

	var drainWG sync.WaitGroup
	drainWG.Add(1)
	var s1n429, s1n200, s2n429, s2n200 int
	go func(output chan Result) {
		defer drainWG.Done()
		for res := range output {
			switch res.StatusCode {
			case http.StatusTooManyRequests:
				if res.URL == srv1.URL {
					s1n429++
				} else {
					s2n429++
				}
			case http.StatusOK:
				if res.URL == srv1.URL {
					s1n200++
				} else {
					s2n200++
				}
			}
		}
	}(output)

	for _, url := range seed {
		r.process(url, wg, r.hp, httpx.HTTP, so, output, retryCh)
	}

	wg.Wait()
	wait()
	cancel()

	close(retryCh)
	close(output)
	drainWG.Wait()

	require.Equal(t, 3, s1n429)
	require.Equal(t, 1, s1n200)
	require.Equal(t, 2, s2n429)
	require.Equal(t, 1, s2n200)
}
