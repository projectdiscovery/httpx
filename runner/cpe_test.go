package runner

import (
	"testing"
)

func TestSanitizeCPEVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain semver", "2.4.7", "2.4.7"},
		{"uppercase", "1.0.0-RC1", "1.0.0-rc1"},
		{"spaces to underscore", "10 0", "10_0"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeCPEVersion(tt.in); got != tt.want {
				t.Fatalf("sanitizeCPEVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSetCPEVersion(t *testing.T) {
	tests := []struct {
		name    string
		cpe     string
		version string
		want    string
	}{
		{
			name:    "fills version slot",
			cpe:     "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
			version: "14.2.3",
			want:    "cpe:2.3:a:vercel:next.js:14.2.3:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version leaves cpe unchanged",
			cpe:     "cpe:2.3:a:apache:apache_http_server:*:*:*:*:*:*:*:*",
			version: "",
			want:    "cpe:2.3:a:apache:apache_http_server:*:*:*:*:*:*:*:*",
		},
		{
			name:    "empty cpe stays empty",
			cpe:     "",
			version: "1.2.3",
			want:    "",
		},
		{
			name:    "malformed cpe returned unchanged",
			cpe:     "not-a-cpe",
			version: "1.2.3",
			want:    "not-a-cpe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := setCPEVersion(tt.cpe, tt.version); got != tt.want {
				t.Fatalf("setCPEVersion(%q, %q) = %q, want %q", tt.cpe, tt.version, got, tt.want)
			}
		})
	}
}
