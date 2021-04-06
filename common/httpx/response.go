package httpx

import (
	"strings"
	"time"
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
	TLSData       *TLSData
	CSPData       *CSPData
	HTTP2         bool
	Pipeline      bool
	Duration      time.Duration
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
func (r *Response) GetHeaderPart(name, sep string) string {
	v, ok := r.Headers[name]
	if ok && len(v) > 0 {
		tokens := strings.Split(strings.Join(v, " "), sep)
		return tokens[0]
	}

	return ""
}

// GetHeadersMap returns a map[string]string of response headers
func (r *Response) GetHeadersMap() map[string]string {
	headers := make(map[string]string, len(r.Headers))

	builder := &strings.Builder{}
	for key, value := range r.Headers {
		for i, v := range value {
			builder.WriteString(v)
			if i != len(value)-1 {
				builder.WriteString(", ")
			}
		}
		headerValue := builder.String()

		headers[key] = headerValue
		builder.Reset()
	}
	return headers
}
