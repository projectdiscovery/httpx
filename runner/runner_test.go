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

func TestRunner_vhostInput_targets(t *testing.T) {
	options := &Options{
		VHostInput: true,
	}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	
	tests := []struct {
		name     string
		input    string
		expected []httpx.Target
	}{
		{
			name:  "basic vhost input without scheme",
			input: "example.com[127.0.0.1]",
			expected: []httpx.Target{{
				Host:     "example.com",
				CustomIP: "127.0.0.1",
			}},
		},
		{
			name:  "vhost input with http scheme",
			input: "http://example.com[192.168.1.1]",
			expected: []httpx.Target{{
				Host:     "http://example.com",
				CustomIP: "192.168.1.1",
			}},
		},
		{
			name:  "vhost input with https scheme",
			input: "https://example.com[10.0.0.1]",
			expected: []httpx.Target{{
				Host:     "https://example.com",
				CustomIP: "10.0.0.1",
			}},
		},
		{
			name:  "vhost input with IPv6",
			input: "example.com[2001:db8::1]",
			expected: []httpx.Target{{
				Host:     "example.com",
				CustomIP: "2001:db8::1",
			}},
		},
		{
			name:  "vhost input with port",
			input: "example.com:8080[127.0.0.1]",
			expected: []httpx.Target{{
				Host:     "example.com:8080",
				CustomIP: "127.0.0.1",
			}},
		},
		{
			name:  "vhost input with scheme and port",
			input: "https://example.com:8443[127.0.0.1]",
			expected: []httpx.Target{{
				Host:     "https://example.com:8443",
				CustomIP: "127.0.0.1",
			}},
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := []httpx.Target{}
			for target := range r.targets(r.hp, tc.input) {
				got = append(got, target)
			}
			require.ElementsMatch(t, tc.expected, got, "incorrect vhost-input parsing for %s", tc.name)
		})
	}
}

func TestRunner_vhostInput_invalidFormats(t *testing.T) {
	options := &Options{
		VHostInput: true,
	}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	
	// Test invalid vhost formats - these should be silently skipped
	invalidVhostInputs := []string{
		"example.com[]",         // empty brackets
		"example.com[",          // unclosed bracket
		"[127.0.0.1]",           // no hostname
	}
	
	for _, input := range invalidVhostInputs {
		got := []httpx.Target{}
		for target := range r.targets(r.hp, input) {
			got = append(got, target)
		}
		// Invalid vhost inputs should produce no targets
		require.Empty(t, got, "invalid vhost-input %s should produce no targets", input)
	}
	
	// Test inputs that should be treated as regular targets (not vhost)
	// Note: "example.com]" will match the vhost pattern but fail parsing, so it produces no target
	regularInputs := []string{
		"example.com",           // no brackets - regular target
	}
	
	for _, input := range regularInputs {
		got := []httpx.Target{}
		for target := range r.targets(r.hp, input) {
			got = append(got, target)
		}
		require.Len(t, got, 1, "expected one target for input %s", input)
		require.Equal(t, input, got[0].Host, "host should match input")
		require.Empty(t, got[0].CustomIP, "regular input %s should not set CustomIP", input)
	}
	
	// Test that inputs with partial brackets are silently skipped when vhost parsing fails
	partialBracketInputs := []string{
		"example.com]",          // no opening bracket
	}
	
	for _, input := range partialBracketInputs {
		got := []httpx.Target{}
		for target := range r.targets(r.hp, input) {
			got = append(got, target)
		}
		// These match the vhost pattern but fail parsing, so no target is produced
		require.Empty(t, got, "partial bracket input %s should produce no targets", input)
	}
}

func TestParseVhostInput(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectHost   string
		expectIP     string
		expectError  bool
	}{
		{
			name:        "basic hostname with IP",
			input:       "example.com[127.0.0.1]",
			expectHost:  "example.com",
			expectIP:    "127.0.0.1",
			expectError: false,
		},
		{
			name:        "hostname with port and IP",
			input:       "example.com:8080[192.168.1.100]",
			expectHost:  "example.com:8080",
			expectIP:    "192.168.1.100",
			expectError: false,
		},
		{
			name:        "scheme with hostname and IP",
			input:       "https://example.com[10.10.10.10]",
			expectHost:  "https://example.com",
			expectIP:    "10.10.10.10",
			expectError: false,
		},
		{
			name:        "full URL with scheme, port and IP",
			input:       "https://example.com:8443[172.16.0.1]",
			expectHost:  "https://example.com:8443",
			expectIP:    "172.16.0.1",
			expectError: false,
		},
		{
			name:        "hostname with IPv6",
			input:       "example.com[2001:db8::1]",
			expectHost:  "example.com",
			expectIP:    "2001:db8::1",
			expectError: false,
		},
		{
			name:        "missing opening bracket",
			input:       "example.com127.0.0.1]",
			expectError: true,
		},
		{
			name:        "missing closing bracket",
			input:       "example.com[127.0.0.1",
			expectError: true,
		},
		{
			name:        "empty brackets",
			input:       "example.com[]",
			expectError: true,
		},
		{
			name:        "no hostname",
			input:       "[127.0.0.1]",
			expectError: true,
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, ip, err := parseVhostInput(tc.input)
			
			if tc.expectError {
				require.NotNil(t, err, "expected error for input %s", tc.input)
			} else {
				require.Nil(t, err, "unexpected error for input %s: %v", tc.input, err)
				require.Equal(t, tc.expectHost, host, "incorrect hostname parsed")
				require.Equal(t, tc.expectIP, ip, "incorrect IP parsed")
			}
		})
	}
}
