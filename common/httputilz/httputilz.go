package httputilz

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

// DumpRequest to string
func DumpRequest(req *retryablehttp.Request) (string, error) {
	dump, err := httputil.DumpRequestOut(req.Request, true)

	return string(dump), err
}

// DumpResponse to string
func DumpResponse(resp *http.Response) (string, error) {
	// httputil.DumpResponse does not work with websockets
	if resp.StatusCode == 101 {
		raw := resp.Status + "\n"
		for h, v := range resp.Header {
			raw += fmt.Sprintf("%s: %s\n", h, v)
		}
		return raw, nil
	}

	raw, err := httputil.DumpResponse(resp, true)
	return string(raw), err
}

// ParseRequest from raw string
func ParseRequest(req string) (method string, path string, headers map[string]string, body string, err error) {
	headers = make(map[string]string)
	reader := bufio.NewReader(strings.NewReader(req))
	s, err := reader.ReadString('\n')
	if err != nil {
		err = fmt.Errorf("could not read request: %s", err)
		return
	}
	parts := strings.Split(s, " ")
	if len(parts) < 3 {
		err = fmt.Errorf("malformed request supplied")
		return
	}
	method = parts[0]

	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if err != nil || line == "" {
			break
		}

		p := strings.SplitN(line, ":", 2)
		if len(p) != 2 {
			continue
		}

		if strings.EqualFold(p[0], "content-length") {
			continue
		}

		p[0] = strings.TrimSpace(p[0])
		p[1] = strings.TrimSpace(p[1])

		headers[p[0]] = p[1]
	}

	// Handle case with the full http url in path. In that case,
	// ignore any host header that we encounter and use the path as request URL
	if strings.HasPrefix(parts[1], "http") {
		var parsed *url.URL
		parsed, err = url.Parse(parts[1])
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
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		err = fmt.Errorf("could not read request body: %s", err)
		return
	}
	body = string(b)
	return
}
