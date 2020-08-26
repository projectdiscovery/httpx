package httpx

import (
	"io"
	"io/ioutil"
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
)

// SupportHTTP2 checks if the target host supports HTTP2
func (h *HTTPX) SupportHTTP2(protocol, method, URL string) bool {
	// http => supports HTTP1.1 => HTTP/2 (H2C)
	if protocol == "http" {
		req, err := retryablehttp.NewRequest(method, URL, nil)
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
		io.Copy(ioutil.Discard, httpresp.Body)
		httpresp.Body.Close()

		return httpresp.StatusCode == 101
	}

	// attempts a direct http2 connection
	req, err := http.NewRequest(method, URL, nil)
	if err != nil {
		return false
	}
	httpresp, err := h.client2.Do(req)
	if err != nil {
		return false
	}
	io.Copy(ioutil.Discard, httpresp.Body)
	httpresp.Body.Close()
	return httpresp.Proto == "HTTP/2.0"
}
