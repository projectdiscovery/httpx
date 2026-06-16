package httpx

import (
	"io"
	"net/http"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

// rawNewLine is the wire-level line terminator used for raw request dumps.
const rawNewLine = "\r\n"

// DumpRequestRaw renders the wire-level representation of an unsafe request,
// mirroring the previous rawhttp.DumpRequestRaw output: the request line, the
// provided headers verbatim (adding Host from the URL only when absent) and the
// body, separated by CRLFs. Content-Length is intentionally not synthesized,
// matching rawhttp's dump behavior.
func DumpRequestRaw(method, rawURL, uriPath string, headers http.Header, body io.Reader) ([]byte, error) {
	u, err := urlutil.ParseURL(rawURL, true)
	if err != nil {
		return nil, err
	}

	h := headers.Clone()
	if h == nil {
		h = http.Header{}
	}
	if _, hasHost := h["Host"]; !hasHost {
		h["Host"] = []string{u.Host}
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	if !u.Params.IsEmpty() {
		path += "?" + u.Params.Encode()
	}
	// override with the custom URI path if specified
	if uriPath != "" {
		path = uriPath
	}

	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1" + rawNewLine)

	for key, values := range h {
		for _, value := range values {
			if value != "" {
				b.WriteString(key + ": " + value + rawNewLine)
			} else {
				b.WriteString(key + rawNewLine)
			}
		}
	}

	b.WriteString(rawNewLine)

	if body != nil {
		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		b.Write(bodyBytes)
	}

	return []byte(b.String()), nil
}
