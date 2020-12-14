package httpx

import (
	"regexp"
	"strings"
)

// ExtractInfo by custom regex from a response
func ExtractInfoByCustomRegex(r *Response, regex string) (info string) {
	var re = regexp.MustCompile(regex)
	matchs := re.FindAllStringSubmatch(r.Raw, -1)
	for _, match := range matchs {
		info += strings.Join(match, "_")
	}
	return
}
