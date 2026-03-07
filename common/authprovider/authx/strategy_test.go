package authx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
)

func TestBasicAuthStrategy(t *testing.T) {
	secret := &Secret{
		Username: "user",
		Password: "pass",
	}
	strategy := NewBasicAuthStrategy(secret)

	t.Run("Apply", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		strategy.Apply(req)

		user, pass, ok := req.BasicAuth()
		if !ok {
			t.Error("Basic auth not set")
		}
		if user != "user" {
			t.Errorf("Username = %v, want user", user)
		}
		if pass != "pass" {
			t.Errorf("Password = %v, want pass", pass)
		}
	})

	t.Run("ApplyOnRR", func(t *testing.T) {
		req, _ := retryablehttp.NewRequest("GET", "http://example.com", nil)
		strategy.ApplyOnRR(req)

		user, pass, ok := req.BasicAuth()
		if !ok {
			t.Error("Basic auth not set")
		}
		if user != "user" {
			t.Errorf("Username = %v, want user", user)
		}
		if pass != "pass" {
			t.Errorf("Password = %v, want pass", pass)
		}
	})
}

func TestBearerTokenAuthStrategy(t *testing.T) {
	secret := &Secret{
		Token: "mytoken123",
	}
	strategy := NewBearerTokenAuthStrategy(secret)

	t.Run("Apply", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		strategy.Apply(req)

		auth := req.Header.Get("Authorization")
		expected := "Bearer mytoken123"
		if auth != expected {
			t.Errorf("Authorization = %v, want %v", auth, expected)
		}
	})

	t.Run("ApplyOnRR", func(t *testing.T) {
		req, _ := retryablehttp.NewRequest("GET", "http://example.com", nil)
		strategy.ApplyOnRR(req)

		auth := req.Header.Get("Authorization")
		expected := "Bearer mytoken123"
		if auth != expected {
			t.Errorf("Authorization = %v, want %v", auth, expected)
		}
	})
}

func TestHeadersAuthStrategy(t *testing.T) {
	// Headers strategy preserves exact casing, so use exact key names
	secret := &Secret{
		Headers: []KV{
			{Key: "X-API-Key", Value: "secret123"},
			{Key: "X-Custom", Value: "value"},
		},
	}
	strategy := NewHeadersAuthStrategy(secret)

	t.Run("Apply", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		strategy.Apply(req)

		// Use direct map access since headers preserve exact casing
		//nolint
		if got := req.Header["X-API-Key"]; len(got) == 0 || got[0] != "secret123" {
			t.Errorf("X-API-Key = %v, want [secret123]", got)
		}
		if got := req.Header["X-Custom"]; len(got) == 0 || got[0] != "value" {
			t.Errorf("X-Custom = %v, want [value]", got)
		}
	})

	t.Run("ApplyOnRR", func(t *testing.T) {
		req, _ := retryablehttp.NewRequest("GET", "http://example.com", nil)
		strategy.ApplyOnRR(req)

		// Use direct map access since headers preserve exact casing
		//nolint
		if got := req.Header["X-API-Key"]; len(got) == 0 || got[0] != "secret123" {
			t.Errorf("X-API-Key = %v, want [secret123]", got)
		}
		if got := req.Header["X-Custom"]; len(got) == 0 || got[0] != "value" {
			t.Errorf("X-Custom = %v, want [value]", got)
		}
	})
}

func TestCookiesAuthStrategy(t *testing.T) {
	secret := &Secret{
		Cookies: []Cookie{
			{Key: "session", Value: "abc123"},
			{Key: "auth", Value: "xyz789"},
		},
	}
	strategy := NewCookiesAuthStrategy(secret)

	t.Run("Apply", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		strategy.Apply(req)

		cookies := req.Cookies()
		if len(cookies) != 2 {
			t.Errorf("Expected 2 cookies, got %d", len(cookies))
		}

		found := make(map[string]string)
		for _, c := range cookies {
			found[c.Name] = c.Value
		}
		if found["session"] != "abc123" {
			t.Errorf("session cookie = %v, want abc123", found["session"])
		}
		if found["auth"] != "xyz789" {
			t.Errorf("auth cookie = %v, want xyz789", found["auth"])
		}
	})

	t.Run("ApplyOnRR replaces existing cookies", func(t *testing.T) {
		req, _ := retryablehttp.NewRequest("GET", "http://example.com", nil)
		// Add existing cookie that should be replaced
		req.AddCookie(&http.Cookie{Name: "session", Value: "old_value"})
		// Add existing cookie that should be kept
		req.AddCookie(&http.Cookie{Name: "other", Value: "keep_me"})

		strategy.ApplyOnRR(req)

		cookies := req.Cookies()
		found := make(map[string]string)
		for _, c := range cookies {
			found[c.Name] = c.Value
		}

		// New cookie values should override old ones
		if found["session"] != "abc123" {
			t.Errorf("session cookie = %v, want abc123", found["session"])
		}
		if found["auth"] != "xyz789" {
			t.Errorf("auth cookie = %v, want xyz789", found["auth"])
		}
		// Existing non-replaced cookie should be preserved
		if found["other"] != "keep_me" {
			t.Errorf("other cookie = %v, want keep_me", found["other"])
		}
	})
}

func TestQueryAuthStrategy(t *testing.T) {
	secret := &Secret{
		Params: []KV{
			{Key: "api_key", Value: "secret123"},
			{Key: "token", Value: "abc"},
		},
	}
	strategy := NewQueryAuthStrategy(secret)

	t.Run("Apply", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com/path?existing=value", nil)
		strategy.Apply(req)

		query := req.URL.Query()
		if got := query.Get("api_key"); got != "secret123" {
			t.Errorf("api_key = %v, want secret123", got)
		}
		if got := query.Get("token"); got != "abc" {
			t.Errorf("token = %v, want abc", got)
		}
		if got := query.Get("existing"); got != "value" {
			t.Errorf("existing = %v, want value", got)
		}
	})

	t.Run("ApplyOnRR", func(t *testing.T) {
		req, _ := retryablehttp.NewRequest("GET", "http://example.com/path?existing=value", nil)
		strategy.ApplyOnRR(req)

		query := req.Request.URL.Query()
		if got := query.Get("api_key"); got != "secret123" {
			t.Errorf("api_key = %v, want secret123", got)
		}
		if got := query.Get("token"); got != "abc" {
			t.Errorf("token = %v, want abc", got)
		}
		if got := query.Get("existing"); got != "value" {
			t.Errorf("existing = %v, want value", got)
		}
	})
}
