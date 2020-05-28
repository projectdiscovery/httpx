package stringz

import "strings"

func TrimProtocol(URL string) string {
	URL = strings.TrimSpace(URL)
	if strings.HasPrefix(strings.ToLower(URL), "http://") || strings.HasPrefix(strings.ToLower(URL), "https://") {
		URL = URL[strings.Index(URL, "//")+2:]
	}

	return URL
}
