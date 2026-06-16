package httpx

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"time"
)

// TraceEventInfo captures a single httptrace event with its timestamp.
type TraceEventInfo struct {
	Time time.Time
	Info interface{}
}

// TraceInfo aggregates the httptrace events collected for a request. It mirrors
// the shape previously provided by retryablehttp so the JSON `trace` output is
// unchanged.
type TraceInfo struct {
	GotConn              TraceEventInfo
	DNSDone              TraceEventInfo
	GetConn              TraceEventInfo
	PutIdleConn          TraceEventInfo
	GotFirstResponseByte TraceEventInfo
	Got100Continue       TraceEventInfo
	DNSStart             TraceEventInfo
	ConnectStart         TraceEventInfo
	ConnectDone          TraceEventInfo
	TLSHandshakeStart    TraceEventInfo
	TLSHandshakeDone     TraceEventInfo
	WroteHeaders         TraceEventInfo
	WroteRequest         TraceEventInfo
}

type traceCtxKey struct{}

// withTrace attaches a TraceInfo collector and the corresponding
// httptrace.ClientTrace to the request context. The reqx transport delegates to
// net/http.Transport in standard mode, so these hooks fire as usual.
func withTrace(req *http.Request) *http.Request {
	traceInfo := &TraceInfo{}
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			traceInfo.GotConn = TraceEventInfo{Time: time.Now(), Info: connInfo}
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			traceInfo.DNSDone = TraceEventInfo{Time: time.Now(), Info: dnsInfo}
		},
		GetConn: func(hostPort string) {
			traceInfo.GetConn = TraceEventInfo{Time: time.Now(), Info: hostPort}
		},
		PutIdleConn: func(err error) {
			traceInfo.PutIdleConn = TraceEventInfo{Time: time.Now(), Info: err}
		},
		GotFirstResponseByte: func() {
			traceInfo.GotFirstResponseByte = TraceEventInfo{Time: time.Now()}
		},
		Got100Continue: func() {
			traceInfo.Got100Continue = TraceEventInfo{Time: time.Now()}
		},
		DNSStart: func(di httptrace.DNSStartInfo) {
			traceInfo.DNSStart = TraceEventInfo{Time: time.Now(), Info: di}
		},
		ConnectStart: func(network, addr string) {
			traceInfo.ConnectStart = TraceEventInfo{Time: time.Now(), Info: struct {
				Network, Addr string
			}{network, addr}}
		},
		ConnectDone: func(network, addr string, err error) {
			if err == nil {
				traceInfo.ConnectDone = TraceEventInfo{Time: time.Now(), Info: struct {
					Network, Addr string
					Error         error
				}{network, addr, err}}
			}
		},
		TLSHandshakeStart: func() {
			traceInfo.TLSHandshakeStart = TraceEventInfo{Time: time.Now()}
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err == nil {
				traceInfo.TLSHandshakeDone = TraceEventInfo{Time: time.Now(), Info: struct {
					ConnectionState tls.ConnectionState
					Error           error
				}{cs, err}}
			}
		},
		WroteHeaders: func() {
			traceInfo.WroteHeaders = TraceEventInfo{Time: time.Now()}
		},
		WroteRequest: func(wri httptrace.WroteRequestInfo) {
			traceInfo.WroteRequest = TraceEventInfo{Time: time.Now(), Info: wri}
		},
	}

	ctx := context.WithValue(req.Context(), traceCtxKey{}, traceInfo)
	ctx = httptrace.WithClientTrace(ctx, trace)
	return req.WithContext(ctx)
}

// GetTraceInfo returns the TraceInfo collected for the request, or nil if
// tracing was not enabled for it.
func GetTraceInfo(req *http.Request) *TraceInfo {
	if req == nil {
		return nil
	}
	if ti, ok := req.Context().Value(traceCtxKey{}).(*TraceInfo); ok {
		return ti
	}
	return nil
}
