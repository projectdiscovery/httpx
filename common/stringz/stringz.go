package stringz

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/projectdiscovery/httpx/common/httpx"
)

// TrimProtocol removes the HTTP scheme from an URI
func TrimProtocol(targetURL string) string {
	URL := strings.TrimSpace(targetURL)
	if strings.HasPrefix(strings.ToLower(URL), "http://") || strings.HasPrefix(strings.ToLower(URL), "https://") {
		URL = AddURLDefaultPort(URL)
		URL = URL[strings.Index(URL, "//")+2:]
	}

	return URL
}

// StringToSliceInt converts string to slice of ints
func StringToSliceInt(s string) ([]int, error) {
	var r []int
	if s == "" {
		return r, nil
	}
	for _, v := range strings.Split(s, ",") {
		vTrim := strings.TrimSpace(v)
		if i, err := strconv.Atoi(vTrim); err == nil {
			r = append(r, i)
		} else {
			return r, err
		}
	}

	return r, nil
}

// SplitByCharAndTrimSpace splits string by a character and remove spaces
func SplitByCharAndTrimSpace(s, splitchar string) (result []string) {
	for _, token := range strings.Split(s, splitchar) {
		result = append(result, strings.TrimSpace(token))
	}
	return
}

// AddURLDefaultPort add url default port (80/443) from an URI
// eg:
// http://foo.com -> http://foo.com:80
// https://foo.com -> https://foo.com:443
func AddURLDefaultPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	// http://[::]
	if strings.HasPrefix(u.Host, "[") && strings.HasSuffix(u.Host, "]") {
		if u.Scheme == httpx.HTTPS {
			u.Host = fmt.Sprintf("%s:%s", u.Host, "443")
		} else {
			u.Host = fmt.Sprintf("%s:%s", u.Host, "80")
		}
	}
	// http://foo.com:81
	// http://foo.com
	// http://[::]:80
	if strings.LastIndexByte(u.Host, ':') == -1 {
		if u.Scheme == httpx.HTTPS {
			u.Host = fmt.Sprintf("%s:%s", u.Host, "443")
		} else {
			u.Host = fmt.Sprintf("%s:%s", u.Host, "80")
		}
	}
	return u.String()
}

// RemoveURLDefaultPort remove url default port (80/443) from an URI
// eg:
// http://foo.com:80 -> http://foo.com
// https://foo.com:443 -> https://foo.com
func RemoveURLDefaultPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	colon := strings.LastIndexByte(u.Host, ':')
	if colon != -1 {
		if (u.Scheme == "https" && u.Host[colon+1:] == "443") || u.Scheme == "http" && u.Host[colon+1:] == "80" {
			u.Host = u.Host[:colon]
		}
	}
	return u.String()
}
