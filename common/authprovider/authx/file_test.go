package authx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCookieParse(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantKey   string
		wantValue string
		wantErr   bool
	}{
		{
			name:      "simple cookie",
			raw:       "session=abc123",
			wantKey:   "session",
			wantValue: "abc123",
			wantErr:   false,
		},
		{
			name:      "cookie with Set-Cookie prefix",
			raw:       "Set-Cookie: session=abc123; Path=/",
			wantKey:   "session",
			wantValue: "abc123",
			wantErr:   false,
		},
		{
			name:      "cookie with equals in value",
			raw:       "token=eyJhbGciOiJIUzI1NiJ9==; Path=/",
			wantKey:   "token",
			wantValue: "eyJhbGciOiJIUzI1NiJ9==",
			wantErr:   false,
		},
		{
			name:      "cookie with spaces",
			raw:       " session = abc123 ; Path=/",
			wantKey:   "session",
			wantValue: "abc123",
			wantErr:   false,
		},
		{
			name:    "empty raw",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "missing equals",
			raw:     "sessionabc123; Path=/",
			wantErr: true,
		},
		{
			name:    "empty key",
			raw:     "=abc123; Path=/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cookie{Raw: tt.raw}
			err := c.Parse()

			if (err != nil) != tt.wantErr {
				t.Errorf("Cookie.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if c.Key != tt.wantKey {
					t.Errorf("Cookie.Parse() Key = %v, want %v", c.Key, tt.wantKey)
				}
				if c.Value != tt.wantValue {
					t.Errorf("Cookie.Parse() Value = %v, want %v", c.Value, tt.wantValue)
				}
			}
		})
	}
}

func TestSecretValidate(t *testing.T) {
	tests := []struct {
		name    string
		secret  Secret
		wantErr bool
	}{
		{
			name: "valid basic auth",
			secret: Secret{
				Type:     "BasicAuth",
				Domains:  []string{"example.com"},
				Username: "user",
				Password: "pass",
			},
			wantErr: false,
		},
		{
			name: "valid bearer token",
			secret: Secret{
				Type:    "BearerToken",
				Domains: []string{"example.com"},
				Token:   "abc123",
			},
			wantErr: false,
		},
		{
			name: "valid header auth",
			secret: Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{{Key: "X-API-Key", Value: "secret"}},
			},
			wantErr: false,
		},
		{
			name: "valid cookie auth",
			secret: Secret{
				Type:    "Cookie",
				Domains: []string{"example.com"},
				Cookies: []Cookie{{Key: "session", Value: "abc123"}},
			},
			wantErr: false,
		},
		{
			name: "valid query auth",
			secret: Secret{
				Type:    "Query",
				Domains: []string{"example.com"},
				Params:  []KV{{Key: "api_key", Value: "secret"}},
			},
			wantErr: false,
		},
		{
			name: "invalid type",
			secret: Secret{
				Type:    "InvalidType",
				Domains: []string{"example.com"},
			},
			wantErr: true,
		},
		{
			name: "missing domains",
			secret: Secret{
				Type:     "BasicAuth",
				Username: "user",
				Password: "pass",
			},
			wantErr: true,
		},
		{
			name: "basic auth missing username",
			secret: Secret{
				Type:     "BasicAuth",
				Domains:  []string{"example.com"},
				Password: "pass",
			},
			wantErr: true,
		},
		{
			name: "basic auth missing password",
			secret: Secret{
				Type:     "BasicAuth",
				Domains:  []string{"example.com"},
				Username: "user",
			},
			wantErr: true,
		},
		{
			name: "bearer auth missing token",
			secret: Secret{
				Type:    "BearerToken",
				Domains: []string{"example.com"},
			},
			wantErr: true,
		},
		{
			name: "header auth missing headers",
			secret: Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
			},
			wantErr: true,
		},
		{
			name: "cookie auth missing cookies",
			secret: Secret{
				Type:    "Cookie",
				Domains: []string{"example.com"},
			},
			wantErr: true,
		},
		{
			name: "query auth missing params",
			secret: Secret{
				Type:    "Query",
				Domains: []string{"example.com"},
			},
			wantErr: true,
		},
		{
			name: "valid domain regex",
			secret: Secret{
				Type:         "BearerToken",
				DomainsRegex: []string{".*\\.example\\.com"},
				Token:        "abc123",
			},
			wantErr: false,
		},
		{
			name: "invalid domain regex",
			secret: Secret{
				Type:         "BearerToken",
				DomainsRegex: []string{"[invalid"},
				Token:        "abc123",
			},
			wantErr: true,
		},
		{
			name: "case insensitive type",
			secret: Secret{
				Type:    "basicauth",
				Domains: []string{"example.com"},
				Username: "user",
				Password: "pass",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.secret.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Secret.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetAuthDataFromFile(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	yamlContent := `id: test
info:
  name: test
static:
  - type: BasicAuth
    domains:
      - example.com
    username: user
    password: pass
`

	jsonContent := `{
  "id": "test",
  "info": {"name": "test"},
  "static": [
    {
      "type": "BasicAuth",
      "domains": ["example.com"],
      "username": "user",
      "password": "pass"
    }
  ]
}`

	tests := []struct {
		name     string
		filename string
		content  string
		wantErr  bool
	}{
		{
			name:     "yaml file lowercase",
			filename: "secrets.yaml",
			content:  yamlContent,
			wantErr:  false,
		},
		{
			name:     "yml file lowercase",
			filename: "secrets.yml",
			content:  yamlContent,
			wantErr:  false,
		},
		{
			name:     "json file lowercase",
			filename: "secrets.json",
			content:  jsonContent,
			wantErr:  false,
		},
		{
			name:     "yaml file uppercase",
			filename: "secrets.YAML",
			content:  yamlContent,
			wantErr:  false,
		},
		{
			name:     "json file uppercase",
			filename: "secrets.JSON",
			content:  jsonContent,
			wantErr:  false,
		},
		{
			name:     "invalid extension",
			filename: "secrets.txt",
			content:  yamlContent,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			filePath := filepath.Join(tmpDir, tt.filename)
			err := os.WriteFile(filePath, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			_, err = GetAuthDataFromFile(filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAuthDataFromFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSecretGetStrategy(t *testing.T) {
	tests := []struct {
		name       string
		secret     Secret
		wantType   string
		wantNil    bool
	}{
		{
			name: "basic auth strategy",
			secret: Secret{
				Type:     "BasicAuth",
				Username: "user",
				Password: "pass",
			},
			wantType: "*authx.BasicAuthStrategy",
			wantNil:  false,
		},
		{
			name: "bearer token strategy",
			secret: Secret{
				Type:  "BearerToken",
				Token: "abc123",
			},
			wantType: "*authx.BearerTokenAuthStrategy",
			wantNil:  false,
		},
		{
			name: "header strategy",
			secret: Secret{
				Type:    "Header",
				Headers: []KV{{Key: "X-API-Key", Value: "secret"}},
			},
			wantType: "*authx.HeadersAuthStrategy",
			wantNil:  false,
		},
		{
			name: "cookie strategy",
			secret: Secret{
				Type:    "Cookie",
				Cookies: []Cookie{{Key: "session", Value: "abc123"}},
			},
			wantType: "*authx.CookiesAuthStrategy",
			wantNil:  false,
		},
		{
			name: "query strategy",
			secret: Secret{
				Type:   "Query",
				Params: []KV{{Key: "api_key", Value: "secret"}},
			},
			wantType: "*authx.QueryAuthStrategy",
			wantNil:  false,
		},
		{
			name: "unknown type returns nil",
			secret: Secret{
				Type: "UnknownType",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := tt.secret.GetStrategy()
			if tt.wantNil {
				if strategy != nil {
					t.Errorf("GetStrategy() = %T, want nil", strategy)
				}
			} else {
				if strategy == nil {
					t.Errorf("GetStrategy() = nil, want %s", tt.wantType)
				}
			}
		})
	}
}
