package stringz

import (
	"strconv"
	"strings"
)

// TrimProtocol removes the HTTP scheme from an URI
func TrimProtocol(targetURL string) string {
	URL := strings.TrimSpace(targetURL)
	if strings.HasPrefix(strings.ToLower(URL), "http://") || strings.HasPrefix(strings.ToLower(URL), "https://") {
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
