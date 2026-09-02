package runner

import (
	"net"
	"net/http"
	"strconv"

	"github.com/projectdiscovery/httpx/common/httpx"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var commonHttpPorts = []string{
	"80",
	"8080",
}

// determineMostLikelySchemeOrder for the input
func determineMostLikelySchemeOrder(input string) string {
	if _, port, err := net.SplitHostPort(input); err == nil {
		// if input has port that is commonly used for HTTP, return http then https
		if sliceutil.Contains(commonHttpPorts, port) {
			return httpx.HTTP
		}

		// As of 10/2025 shodan shows that ports > 1024 are more likely to expose HTTP
		// hence we test first http then https on higher ports
		// if input has port > 1024, return http then https
		if port, err := strconv.Atoi(port); err == nil && port > 1024 {
			return httpx.HTTP
		}
	}

	return httpx.HTTPS
}

// tlsRequiredSignals are the phrases a TLS listener returns when a plaintext
// request reaches it. They arrive as a perfectly valid HTTP 400, so nothing in
// the transport layer flags them and the scheme retry never fires.
var tlsRequiredSignals = []string{
	"plain http request was sent to https port",
	"http request was sent to an https port",
	"combination of host and port requires tls",
	"speaking plain http to an ssl-enabled server port",
	"client sent an http request to an https server",
}

// respondsOnlyOverTLS reports whether a plaintext response is a TLS listener
// rejecting the request rather than a real HTTP service. A bare
// "400 Bad Request" is a legitimate HTTP answer and is deliberately not
// matched, so only the distinctive server phrasings trigger a scheme retry.
func respondsOnlyOverTLS(resp *httpx.Response) bool {
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		return false
	}

	haystack := resp.Raw
	if haystack == "" {
		haystack = string(resp.Data)
	}
	return stringsutil.ContainsAnyI(haystack, tlsRequiredSignals...)
}
