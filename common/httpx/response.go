package httpx

import (
	"strings"
	"time"

	"github.com/projectdiscovery/httputil"
)

// Response contains the response to a server
type Response struct {
	StatusCode    int
	Headers       map[string][]string
	Data          []byte
	ContentLength int
	Raw           string
	RawHeaders    string
	Words         int
	Lines         int
	TLSData       *TLSData
	CSPData       *CSPData
	HTTP2         bool
	Pipeline      bool
	Duration      time.Duration
	Chain         []httputil.ChainItem
}

// ChainItem request=>response
type ChainItem struct {
	Request    []byte
	Response   []byte
	StatusCode int
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

// GetChainStatusCodes from redirects
func (r *Response) GetChainStatusCodes() []int {
	var statusCodes []int
	for _, chainItem := range r.Chain {
		statusCodes = append(statusCodes, chainItem.StatusCode)
	}
	return statusCodes
}

// GetChain dump the whole redirect chain
func (r *Response) GetChain() string {
	var respchain strings.Builder
	for _, chainItem := range r.Chain {
		respchain.Write(chainItem.Request)
		respchain.Write(chainItem.Response)
	}
	return respchain.String()
}
