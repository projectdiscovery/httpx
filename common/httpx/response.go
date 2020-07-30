package httpx

import (
	"strings"
)

// Response contains the response to a server
type Response struct {
	StatusCode    int
	Headers       map[string][]string
	Data          []byte
	ContentLength int
	Raw           string
	Words         int
	Lines         int
	TlsData       *TlsData
}

// GetHeader value
func (r *Response) GetHeader(name string) string {
	v, ok := r.Headers[name]
	if ok {
		return strings.Join(v, " ")
	}

	return ""
}

// GetHeaderPart with offset
func (r *Response) GetHeaderPart(name string, at int) string {
	v, ok := r.Headers[name]
	if ok && at < len(v) {
		return v[at]
	}

	return ""
}
