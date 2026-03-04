package httpx

type Proto string

const (
	UNKNOWN Proto = ""
	// HTTP11 defines HTTP/1.1 only protocol. Disables HTTP/2 transport and fallback.
HTTP11  Proto = "http11"
	HTTP2   Proto = "http2"
	HTTP3   Proto = "http3"
)
