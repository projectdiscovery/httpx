package runner

import (
	"net"
	"strconv"

	"github.com/projectdiscovery/httpx/common/httpx"
	sliceutil "github.com/projectdiscovery/utils/slice"
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
