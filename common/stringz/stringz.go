package stringz

import (
	"strconv"
	"strings"

	"github.com/projectdiscovery/urlutil"
)

// TrimProtocol removes the HTTP scheme from an URI
func TrimProtocol(targetURL string, addDefaultPort bool) string {
	URL := strings.TrimSpace(targetURL)
	if strings.HasPrefix(strings.ToLower(URL), "http://") || strings.HasPrefix(strings.ToLower(URL), "https://") {
		if addDefaultPort {
			URL = AddURLDefaultPort(URL)
			URL = URL[strings.Index(URL, "//")+2:]
		}
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
	u, err := urlutil.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.String()
}

// RemoveURLDefaultPort remove url default port (80/443) from an URI
// eg:
// http://foo.com:80 -> http://foo.com
// https://foo.com:443 -> https://foo.com
func RemoveURLDefaultPort(rawURL string) string {
	u, err := urlutil.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	if u.Scheme == urlutil.HTTP && u.Port == "80" || u.Scheme == urlutil.HTTPS && u.Port == "443" {
		u.Port = ""
	}
	return u.String()
}
