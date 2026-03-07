package authprovider

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	urlutil "github.com/projectdiscovery/utils/url"
)

func createTestSecretsFile(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "secrets.yaml")
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test secrets file: %v", err)
	}
	return filePath
}

func TestFileAuthProviderLookupAddr(t *testing.T) {
	content := `id: test
info:
  name: test
static:
  - type: BasicAuth
    domains:
      - example.com
      - api.example.com:443
    username: user
    password: pass
  - type: BearerToken
    domains-regex:
      - ".*\\.test\\.com"
    token: regextoken
`
	filePath := createTestSecretsFile(t, content)
	provider, err := NewFileAuthProvider(filePath)
	if err != nil {
		t.Fatalf("NewFileAuthProvider() error = %v", err)
	}

	tests := []struct {
		name      string
		addr      string
		wantCount int
	}{
		{
			name:      "exact match",
			addr:      "example.com",
			wantCount: 1,
		},
		{
			name:      "exact match case insensitive",
			addr:      "EXAMPLE.COM",
			wantCount: 1,
		},
		{
			name:      "with port 443 normalized",
			addr:      "example.com:443",
			wantCount: 1,
		},
		{
			name:      "with port 80 normalized",
			addr:      "example.com:80",
			wantCount: 1,
		},
		{
			name:      "subdomain exact match",
			addr:      "api.example.com",
			wantCount: 1,
		},
		{
			name:      "regex match",
			addr:      "foo.test.com",
			wantCount: 1,
		},
		{
			name:      "regex match subdomain",
			addr:      "bar.baz.test.com",
			wantCount: 1,
		},
		{
			name:      "no match",
			addr:      "unknown.com",
			wantCount: 0,
		},
		{
			name:      "non-standard port not normalized",
			addr:      "example.com:8080",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategies := provider.LookupAddr(tt.addr)
			if len(strategies) != tt.wantCount {
				t.Errorf("LookupAddr(%q) returned %d strategies, want %d", tt.addr, len(strategies), tt.wantCount)
			}
		})
	}
}

func TestFileAuthProviderLookupURL(t *testing.T) {
	content := `id: test
info:
  name: test
static:
  - type: BasicAuth
    domains:
      - example.com
    username: user
    password: pass
`
	filePath := createTestSecretsFile(t, content)
	provider, err := NewFileAuthProvider(filePath)
	if err != nil {
		t.Fatalf("NewFileAuthProvider() error = %v", err)
	}

	t.Run("LookupURL", func(t *testing.T) {
		u, _ := url.Parse("https://example.com/path")
		strategies := provider.LookupURL(u)
		if len(strategies) != 1 {
			t.Errorf("LookupURL() returned %d strategies, want 1", len(strategies))
		}
	})

	t.Run("LookupURLX", func(t *testing.T) {
		u, _ := urlutil.Parse("https://example.com/path")
		strategies := provider.LookupURLX(u)
		if len(strategies) != 1 {
			t.Errorf("LookupURLX() returned %d strategies, want 1", len(strategies))
		}
	})
}

func TestMultiAuthProvider(t *testing.T) {
	content1 := `id: test1
info:
  name: test1
static:
  - type: BasicAuth
    domains:
      - first.com
    username: user1
    password: pass1
`
	content2 := `id: test2
info:
  name: test2
static:
  - type: BearerToken
    domains:
      - second.com
    token: token2
`
	filePath1 := createTestSecretsFile(t, content1)
	provider1, err := NewFileAuthProvider(filePath1)
	if err != nil {
		t.Fatalf("NewFileAuthProvider() error = %v", err)
	}

	// Create second file in different temp dir
	tmpDir2 := t.TempDir()
	filePath2 := filepath.Join(tmpDir2, "secrets2.yaml")
	err = os.WriteFile(filePath2, []byte(content2), 0644)
	if err != nil {
		t.Fatalf("Failed to create test secrets file: %v", err)
	}
	provider2, err := NewFileAuthProvider(filePath2)
	if err != nil {
		t.Fatalf("NewFileAuthProvider() error = %v", err)
	}

	multi := NewMultiAuthProvider(provider1, provider2)

	tests := []struct {
		name      string
		addr      string
		wantCount int
	}{
		{
			name:      "match first provider",
			addr:      "first.com",
			wantCount: 1,
		},
		{
			name:      "match second provider",
			addr:      "second.com",
			wantCount: 1,
		},
		{
			name:      "no match",
			addr:      "third.com",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategies := multi.LookupAddr(tt.addr)
			if len(strategies) != tt.wantCount {
				t.Errorf("LookupAddr(%q) returned %d strategies, want %d", tt.addr, len(strategies), tt.wantCount)
			}
		})
	}
}

func TestNewFileAuthProviderErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "empty secrets",
			content: `id: test`,
			wantErr: true,
		},
		{
			name: "invalid secret type",
			content: `id: test
static:
  - type: InvalidType
    domains:
      - example.com
`,
			wantErr: true,
		},
		{
			name: "missing required field",
			content: `id: test
static:
  - type: BasicAuth
    domains:
      - example.com
    username: user
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := createTestSecretsFile(t, tt.content)
			_, err := NewFileAuthProvider(filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFileAuthProvider() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
