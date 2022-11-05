package httputilz

import (
	"bufio"
	"fmt"
	"io"
	"net/http/httputil"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	headerParts  = 2
	requestParts = 3
)

// DumpRequest to string
func DumpRequest(req *retryablehttp.Request) (string, error) {
	dump, err := httputil.DumpRequestOut(req.Request, true)

	return string(dump), err
}

// ParseRequest from raw string
func ParseRequest(req string, unsafe bool) (method, path string, headers map[string]string, body string, err error) {
	headers = make(map[string]string)
	reader := bufio.NewReader(strings.NewReader(req))
	s, err := reader.ReadString('\n')
	if err != nil {
		err = fmt.Errorf("could not read request: %s", err)
		return
	}
	parts := strings.Split(s, " ")
	if len(parts) < requestParts {
		err = fmt.Errorf("malformed request supplied")
		return
	}
	method = parts[0]

	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if readErr != nil || line == "" {
			break
		}

		// Unsafe skips all checks
		p := strings.SplitN(line, ":", headerParts)
		key := p[0]
		value := ""
		if len(p) == headerParts {
			value = p[1]
		}

		if !unsafe {
			if len(p) != headerParts {
				continue
			}

			if strings.EqualFold(key, "content-length") {
				continue
			}

			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
		}

		headers[key] = value
	}

	// Handle case with the full http url in path. In that case,
	// ignore any host header that we encounter and use the path as request URL
	if strings.HasPrefix(parts[1], "http") {
		var parsed *urlutil.URL
		parsed, err = urlutil.Parse(parts[1])
		if err != nil {
			err = fmt.Errorf("could not parse request URL: %s", err)
			return
		}
		path = parts[1]
		headers["Host"] = parsed.Host
	} else {
		path = parts[1]
	}

	// Set the request body
	b, err := io.ReadAll(reader)
	if err != nil {
		err = fmt.Errorf("could not read request body: %s", err)
		return
	}
	body = string(b)

	return method, path, headers, body, nil
}
