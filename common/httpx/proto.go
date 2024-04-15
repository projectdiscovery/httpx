package httpx

type Proto string

const (
	AUTO   Proto = "auto"
	HTTP11 Proto = "http11"
	HTTP2  Proto = "http2"
	HTTP3  Proto = "http3"
)
