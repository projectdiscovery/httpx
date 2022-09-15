package httpx

import (
	"net/http"

	"github.com/projectdiscovery/cryptoutil"
)

// TLSGrab fills the TLSData
func (h *HTTPX) TLSGrab(r *http.Response) *cryptoutil.TLSData {
	if r.TLS != nil {
		return cryptoutil.TLSGrab(r.TLS)
	}
	return nil
}
