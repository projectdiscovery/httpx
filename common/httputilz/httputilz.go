package httputilz

import (
	"net/http/httputil"

	"github.com/projectdiscovery/retryablehttp-go"
)

// DumpRequest to string
func DumpRequest(req *retryablehttp.Request) (string, error) {
	dump, err := httputil.DumpRequestOut(req.Request, true)

	return string(dump), err
}
