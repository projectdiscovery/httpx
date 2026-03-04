package httpx

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDisableHTTPFallbackBlocks(t *testing.T) {
	opts := &Options{
		Protocol:            "http11",
		DisableHTTPFallback: true,
		Timeout:             5 * time.Second,
		RetryMax:            3,
	}

	client, err := NewClient(opts)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	checkRetry := client.NewCheckRetryFunc()
	http2Error := errors.New(
		"net/http: HTTP/1.x transport connection broken: malformed HTTP version \"HTTP/2\"")

	shouldRetry, returnedErr := checkRetry(context.Background(), nil, http2Error)

	if shouldRetry {
		t.Error("Expected shouldRetry=false when DisableHTTPFallback=true")
	}
	if returnedErr == nil {
		t.Error("Expected error to be returned")
	}
}

func TestDisableHTTPFallbackAllows(t *testing.T) {
	opts := &Options{
		Protocol:            "http11",
		DisableHTTPFallback: false,
		Timeout:             5 * time.Second,
		RetryMax:            3,
	}

	client, err := NewClient(opts)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	checkRetry := client.NewCheckRetryFunc()
	http2Error := errors.New(
		"net/http: HTTP/1.x transport connection broken: malformed HTTP version \"HTTP/2\"")

	shouldRetry, _ := checkRetry(context.Background(), nil, http2Error)

	if !shouldRetry {
		t.Error("Expected shouldRetry=true when DisableHTTPFallback=false")
	}
}

func TestNonHTTP2ErrorsRetry(t *testing.T) {
	opts := &Options{
		Protocol:            "http11",
		DisableHTTPFallback: true,
		Timeout:             5 * time.Second,
		RetryMax:            3,
	}

	client, err := NewClient(opts)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	checkRetry := client.NewCheckRetryFunc()
	timeoutErr := errors.New("context deadline exceeded")

	shouldRetry, _ := checkRetry(context.Background(), nil, timeoutErr)

	if !shouldRetry {
		t.Error("Expected timeout error to still trigger retry")
	}
}

func TestIsHTTP2FallbackError(t *testing.T) {
	testCases := []struct {
		name        string
		errMsg      string
		shouldMatch bool
	}{
		{
			name:        "Malformed HTTP/2 version",
			errMsg:      "malformed HTTP version \"HTTP/2\"",
			shouldMatch: true,
		},
		{
			name:        "Malformed HTTP response",
			errMsg:      "malformed HTTP response",
			shouldMatch: true,
		},
		{
			name:        "Generic error",
			errMsg:      "connection refused",
			shouldMatch: false,
		},
		{
			name:        "Timeout error",
			errMsg:      "context deadline exceeded",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := errors.New(tc.errMsg)
			result := isHTTP2FallbackError(err)

			if result != tc.shouldMatch {
				t.Errorf("Expected %v, got %v for: %s", tc.shouldMatch, result, tc.errMsg)
			}
		})
	}
}

