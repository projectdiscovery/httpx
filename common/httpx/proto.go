package httpx

// Proto identifies the HTTP protocol version to use for requests.
type Proto string

const (
	// UNKNOWN leaves the protocol unspecified, letting the client negotiate.
	UNKNOWN Proto = ""
	// HTTP11 enforces HTTP/1.1 and disables HTTP/2 negotiation.
	HTTP11 Proto = "http11"
	// HTTP2 requests HTTP/2 for all connections.
	HTTP2 Proto = "http2"
	// HTTP3 requests HTTP/3 (QUIC) for all connections.
	HTTP3 Proto = "http3"
)
