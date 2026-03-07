package authx

import (
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	_ AuthStrategy = &CookiesAuthStrategy{}
)

// CookiesAuthStrategy is a strategy for cookies auth
type CookiesAuthStrategy struct {
	Data *Secret
}

// NewCookiesAuthStrategy creates a new cookies auth strategy
func NewCookiesAuthStrategy(data *Secret) *CookiesAuthStrategy {
	return &CookiesAuthStrategy{Data: data}
}

// Apply applies the cookies auth strategy to the request
func (s *CookiesAuthStrategy) Apply(req *http.Request) {
	for _, cookie := range s.Data.Cookies {
		req.AddCookie(&http.Cookie{
			Name:  cookie.Key,
			Value: cookie.Value,
		})
	}
}

// ApplyOnRR applies the cookies auth strategy to the retryable request
func (s *CookiesAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	// Build a set of cookie names to replace
	newCookieNames := make(map[string]struct{}, len(s.Data.Cookies))
	for _, cookie := range s.Data.Cookies {
		newCookieNames[cookie.Key] = struct{}{}
	}

	// Filter existing cookies, keeping only those not being replaced
	existingCookies := req.Cookies()
	filteredCookies := make([]*http.Cookie, 0, len(existingCookies))
	for _, cookie := range existingCookies {
		if _, shouldReplace := newCookieNames[cookie.Name]; !shouldReplace {
			filteredCookies = append(filteredCookies, cookie)
		}
	}

	// Clear and reset cookies
	req.Header.Del("Cookie")
	for _, cookie := range filteredCookies {
		req.AddCookie(cookie)
	}
	// Add new cookies
	for _, cookie := range s.Data.Cookies {
		req.AddCookie(&http.Cookie{
			Name:  cookie.Key,
			Value: cookie.Value,
		})
	}
}
