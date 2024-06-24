package httpx

import (
	"strings"
	"time"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	httputil "github.com/projectdiscovery/utils/http"
)

// Response contains the response to a server
type Response struct {
	Input         string // input that was given
	StatusCode    int
	Headers       map[string][]string
	RawData       []byte // undecoded data
	Data          []byte // decoded data
	ContentLength int
	Raw           string
	RawHeaders    string
	Words         int
	Lines         int
	TLSData       *clients.Response
	CSPData       *CSPData
	BodyDomains   *BodyDomain
	HTTP2         bool
	Pipeline      bool
	Duration      time.Duration
	Chain         []httputil.ChainItem
}

// ChainItem request=>response
type ChainItem struct {
	Request    string `json:"request,omitempty"`
	Response   string `json:"response,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Location   string `json:"location,omitempty"`
	RequestURL string `json:"request-url,omitempty"`
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

// GetChain dump the whole redirect chain as string
func (r *Response) GetChain() string {
	var respchain strings.Builder
	for counter, chainItem := range r.Chain {
		if counter != 0 {
			respchain.Write(chainItem.Request)
		}
		if counter < len(r.Chain)-1 {
			respchain.Write(chainItem.Response)
		}
	}
	return respchain.String()
}

// GetChainAsSlice dump the whole redirect chain as structuerd slice
func (r *Response) GetChainAsSlice() (chain []ChainItem) {
	for _, chainItem := range r.Chain {
		chain = append(chain, ChainItem{
			Request:    string(chainItem.Request),
			Response:   string(chainItem.Response),
			StatusCode: chainItem.StatusCode,
			Location:   chainItem.Location,
			RequestURL: chainItem.RequestURL,
		})
	}
	return
}

// HasChain redirects
func (r *Response) HasChain() bool {
	return len(r.Chain) > 1
}

// GetChainLastURL returns the final URL
func (r *Response) GetChainLastURL() string {
	if r.HasChain() {
		lastitem := r.Chain[len(r.Chain)-1]
		return lastitem.RequestURL
	}
	return ""
}
