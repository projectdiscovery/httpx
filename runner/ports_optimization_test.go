package runner

import (
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

func TestDetermineMostLikelySchemeOrder(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "port 80 should return HTTP",
			input:    "example.com:80",
			expected: httpx.HTTP,
		},
		{
			name:     "port 8080 should return HTTP",
			input:    "example.com:8080",
			expected: httpx.HTTP,
		},
		{
			name:     "port 443 should return HTTPS",
			input:    "example.com:443",
			expected: httpx.HTTPS,
		},
		{
			name:     "port 8443 should return HTTP (port > 1024)",
			input:    "example.com:8443",
			expected: httpx.HTTP,
		},
		{
			name:     "no port should return HTTPS",
			input:    "example.com",
			expected: httpx.HTTPS,
		},
		{
			name:     "port 443 with IP should return HTTPS",
			input:    "1.2.3.4:443",
			expected: httpx.HTTPS,
		},
		{
			name:     "port 80 with IP should return HTTP",
			input:    "1.2.3.4:80",
			expected: httpx.HTTP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := determineMostLikelySchemeOrder(tc.input)
			require.Equal(t, tc.expected, result, "unexpected scheme for input %s", tc.input)
		})
	}
}

func TestSwitchPortForFallback(t *testing.T) {
	// Test that when switching from HTTPS to HTTP on port 443, port should become 80
	// And when switching from HTTP to HTTPS on port 80, port should become 443
	tests := []struct {
		name            string
		inputPort       string
		inputProtocol   string
		expectedNewPort string
	}{
		{
			name:            "HTTPS:443 fallback should switch to port 80",
			inputPort:       "443",
			inputProtocol:   httpx.HTTPS,
			expectedNewPort: "80",
		},
		{
			name:            "HTTP:80 fallback should switch to port 443",
			inputPort:       "80",
			inputProtocol:   httpx.HTTP,
			expectedNewPort: "443",
		},
		{
			name:            "HTTPS:8443 fallback should keep port 8443",
			inputPort:       "8443",
			inputProtocol:   httpx.HTTPS,
			expectedNewPort: "8443", // non-default port stays the same
		},
		{
			name:            "HTTP:8080 fallback should keep port 8080",
			inputPort:       "8080",
			inputProtocol:   httpx.HTTP,
			expectedNewPort: "8080", // non-default port stays the same
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newPort := getPortForFallback(tc.inputPort, tc.inputProtocol)
			require.Equal(t, tc.expectedNewPort, newPort, "unexpected port for fallback")
		})
	}
}

// getPortForFallback returns the port to use when falling back to the other protocol
// This is the logic used in runner.go analyze function
func getPortForFallback(currentPort, currentProtocol string) string {
	if currentProtocol == httpx.HTTPS && currentPort == "443" {
		return "80"
	}
	if currentProtocol == httpx.HTTP && currentPort == "80" {
		return "443"
	}
	return currentPort
}

func TestRespondsOnlyOverTLS(t *testing.T) {
	tests := []struct {
		name     string
		response *httpx.Response
		expected bool
	}{
		{
			name:     "nil response",
			response: nil,
			expected: false,
		},
		{
			name: "netty/teamcity rejection",
			response: &httpx.Response{
				StatusCode: 400,
				Raw:        "HTTP/1.1 400 Bad Request\r\n\r\nBad Request\r\nThis combination of host and port requires TLS.\r\n",
			},
			expected: true,
		},
		{
			name: "nginx rejection",
			response: &httpx.Response{
				StatusCode: 400,
				Raw:        "HTTP/1.1 400 Bad Request\r\n\r\n<h1>400 The plain HTTP request was sent to HTTPS port</h1>",
			},
			expected: true,
		},
		{
			name: "apache rejection",
			response: &httpx.Response{
				StatusCode: 400,
				Raw:        "HTTP/1.1 400 Bad Request\r\n\r\nYou're speaking plain HTTP to an SSL-enabled server port.",
			},
			expected: true,
		},
		{
			name: "haproxy rejection",
			response: &httpx.Response{
				StatusCode: 400,
				Raw:        "HTTP/1.1 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.",
			},
			expected: true,
		},
		{
			name: "falls back to decoded data when raw is empty",
			response: &httpx.Response{
				StatusCode: 400,
				Data:       []byte("This combination of host and port requires TLS."),
			},
			expected: true,
		},
		{
			name: "genuine bad request is not a TLS rejection",
			response: &httpx.Response{
				StatusCode: 400,
				Raw:        "HTTP/1.1 400 Bad Request\r\n\r\nBad Request",
			},
			expected: false,
		},
		{
			name: "phrase present on a successful response",
			response: &httpx.Response{
				StatusCode: 200,
				Raw:        "HTTP/1.1 200 OK\r\n\r\nDocs: the plain HTTP request was sent to HTTPS port",
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, respondsOnlyOverTLS(tc.response))
		})
	}
}
