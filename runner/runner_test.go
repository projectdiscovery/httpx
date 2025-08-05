package runner

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

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
	// Test Allow flag blocks IPs outside allowed range
	options := &Options{}
	options.Allow = []string{"192.168.1.0/24"}
	
	runner := &Runner{}
	np, err := runner.createNetworkpolicyInstance(options)
	require.Nil(t, err, "could not create networkpolicy instance")
	require.NotNil(t, np, "networkpolicy instance should not be nil")
	
	// Should block IP outside allowed range
	allowed := np.Validate("8.8.8.8")
	require.False(t, allowed, "IP outside allowed range should be blocked")
	
	// Should allow IP inside allowed range  
	allowed = np.Validate("192.168.1.10")
	require.True(t, allowed, "IP inside allowed range should be allowed")
	
	// Test Deny flag blocks IPs in denied range
	options = &Options{}
	options.Deny = []string{"127.0.0.0/8"}
	
	np, err = runner.createNetworkpolicyInstance(options)
	require.Nil(t, err, "could not create networkpolicy instance")
	
	// Should block IP in denied range
	allowed = np.Validate("127.0.0.1")
	require.False(t, allowed, "IP in denied range should be blocked")
	
	// Should allow IP outside denied range
	allowed = np.Validate("8.8.8.8")
	require.True(t, allowed, "IP outside denied range should be allowed")
	
	// Test combined Allow and Deny flags
	options = &Options{}
	options.Allow = []string{"192.168.0.0/16"}  // Allow 192.168.x.x
	options.Deny = []string{"192.168.1.0/24"}   // But deny 192.168.1.x
	
	np, err = runner.createNetworkpolicyInstance(options)
	require.Nil(t, err, "could not create networkpolicy instance")
	
	// Should block IP outside allowed range (even if not in deny list)
	allowed = np.Validate("10.0.0.1")
	require.False(t, allowed, "IP outside allowed range should be blocked")
	
	// Should block IP in denied range (even if in allowed range)
	allowed = np.Validate("192.168.1.100")
	require.False(t, allowed, "IP in denied range should be blocked even if in allowed range")
	
	// Should allow IP in allowed range but not in denied range
	allowed = np.Validate("192.168.2.50")
	require.True(t, allowed, "IP in allowed range but not in denied range should be allowed")
	
	// Test with multiple Allow and Deny ranges
	options = &Options{}
	options.Allow = []string{"10.0.0.0/8", "172.16.0.0/12"}  // Allow 10.x.x.x and 172.16-31.x.x
	options.Deny = []string{"10.1.0.0/16", "172.20.0.0/16"} // Deny 10.1.x.x and 172.20.x.x
	
	np, err = runner.createNetworkpolicyInstance(options)
	require.Nil(t, err, "could not create networkpolicy instance")
	
	// Test various scenarios
	allowed = np.Validate("10.0.1.1")
	require.True(t, allowed, "10.0.1.1 should be allowed (in allow range, not in deny)")
	
	allowed = np.Validate("10.1.1.1")
	require.False(t, allowed, "10.1.1.1 should be blocked (in deny range)")
	
	allowed = np.Validate("172.16.1.1")
	require.True(t, allowed, "172.16.1.1 should be allowed (in allow range, not in deny)")
	
	allowed = np.Validate("172.20.1.1")
	require.False(t, allowed, "172.20.1.1 should be blocked (in deny range)")
	
	allowed = np.Validate("192.168.1.1")
	require.False(t, allowed, "192.168.1.1 should be blocked (not in any allow range)")
}
