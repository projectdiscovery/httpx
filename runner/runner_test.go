package runner

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/mapcidr/asn"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
