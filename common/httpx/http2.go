package httpx

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
)

const (
	// HTTP defines the plain http scheme
	HTTP = "http"
	// HTTPS defines the secure http scheme
	HTTPS = "https"
	// HTTPorHTTPS defines both http and https scheme in mutual exclusion
	HTTPorHTTPS = "http|https"
	// HTTPandHTTPS defines both http and https scheme
	HTTPandHTTPS = "http&https"
)

// SupportHTTP2 checks if the target host supports HTTP2
func (h *HTTPX) SupportHTTP2(protocol, method, targetURL string) bool {
	// http => supports HTTP1.1 => HTTP/2 (H2C)
	if protocol == HTTP {
		req, err := retryablehttp.NewRequest(method, targetURL, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
		req.Header.Set("Upgrade", "h2c")
		req.Header.Set("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")
		httpresp, err := h.client.Do(req)
		if err != nil {
			return false
		}

		err = freeHTTPResources(httpresp)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			return false
		}

		return httpresp.StatusCode == http.StatusSwitchingProtocols
	}

	// attempts a direct http2 connection
	req, err := http.NewRequestWithContext(context.Background(), method, targetURL, nil)
	if err != nil {
		return false
	}

	httpresp, err := h.client2.Do(req)
	if err != nil {
		return false
	}

	err = freeHTTPResources(httpresp)
	if err != nil {
		gologger.Error().Msgf("%s", err)
		return false
	}

	return httpresp.Proto == "HTTP/2.0"
}

func freeHTTPResources(response *http.Response) error {
	_, err := io.Copy(ioutil.Discard, response.Body)
	if err != nil {
		return fmt.Errorf("could not discard response body: %s", err)
	}

	err = response.Body.Close()
	if err != nil {
		return fmt.Errorf("could not close response body: %s", err)
	}

	return nil
}
