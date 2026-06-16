package authx

import (
	"net/http"
)

var (
	_ AuthStrategy = &BearerTokenAuthStrategy{}
)

// BearerTokenAuthStrategy is a strategy for bearer token auth
type BearerTokenAuthStrategy struct {
	Data *Secret
}

// NewBearerTokenAuthStrategy creates a new bearer token auth strategy
func NewBearerTokenAuthStrategy(data *Secret) *BearerTokenAuthStrategy {
	return &BearerTokenAuthStrategy{Data: data}
}

// Apply applies the bearer token auth strategy to the request
func (s *BearerTokenAuthStrategy) Apply(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+s.Data.Token)
}
