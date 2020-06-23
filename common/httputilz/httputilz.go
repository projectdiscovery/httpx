package httputilz

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/projectdiscovery/retryablehttp-go"
)

// DumpRequest to string
func DumpRequest(req *retryablehttp.Request) (string, error) {
	dump, err := httputil.DumpRequestOut(req.Request, true)

	return string(dump), err
}

// DumpResponse to string
func DumpResponse(resp *http.Response) (string, error) {
	// httputil.DumpResponse does not work with websockets
	if resp.StatusCode == 101 {
		raw := resp.Status + "\n"
		for h, v := range resp.Header {
			raw += fmt.Sprintf("%s: %s\n", h, v)
		}
		return raw, nil
	}

	raw, err := httputil.DumpResponse(resp, true)
	return string(raw), err
}
