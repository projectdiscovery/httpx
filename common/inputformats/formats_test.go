package inputformats

import (
	"strings"
	"testing"
)

func TestGetFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		wantName string
	}{
		{"burp lowercase", "burp", false, "burp"},
		{"burp uppercase", "BURP", false, "burp"},
		{"burp mixed case", "Burp", false, "burp"},
		{"invalid format", "invalid", true, ""},
		{"empty string", "", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetFormat(tt.input)
			if tt.wantNil && got != nil {
				t.Errorf("GetFormat(%q) = %v, want nil", tt.input, got)
			}
			if !tt.wantNil && got == nil {
				t.Errorf("GetFormat(%q) = nil, want non-nil", tt.input)
			}
			if !tt.wantNil && got != nil && got.Name() != tt.wantName {
				t.Errorf("GetFormat(%q).Name() = %q, want %q", tt.input, got.Name(), tt.wantName)
			}
		})
	}
}

func TestSupportedFormats(t *testing.T) {
	supported := SupportedFormats()
	if !strings.Contains(supported, "burp") {
		t.Errorf("SupportedFormats() = %q, expected to contain 'burp'", supported)
	}
}
