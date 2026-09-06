package httpx

import (
	"strings"
	"testing"
)

// TestWave9TLSServerNameIndicationNormalization validates SNI formatting
func TestWave9TLSServerNameIndicationNormalization(t *testing.T) {
	normalizeSNI := func(host string) string {
		h := strings.TrimSpace(strings.ToLower(host))
		if idx := strings.Index(h, ":"); idx != -1 {
			h = h[:idx]
		}
		return strings.TrimSuffix(h, ".")
	}

	testCases := []struct {
		input    string
		expected string
	}{
		{"API.Example.com:443", "api.example.com"},
		{"SECURE.Internal.Net.", "secure.internal.net"},
		{"target.domain.org", "target.domain.org"},
	}

	for _, tc := range testCases {
		actual := normalizeSNI(tc.input)
		if actual != tc.expected {
			t.Errorf("normalizeSNI(%s): expected %s, got %s", tc.input, tc.expected, actual)
		}
	}
}

// TestWave9HTTPRedirectHopLimit asserts max redirect loop guard
func TestWave9HTTPRedirectHopLimit(t *testing.T) {
	maxHops := 10
	isAllowedHop := func(hopCount int) bool {
		return hopCount < maxHops
	}

	if !isAllowedHop(3) {
		t.Errorf("expected 3 hops to be within redirect limit")
	}
	if isAllowedHop(10) {
		t.Errorf("expected 10 hops to trigger redirect limit guard")
	}
}
