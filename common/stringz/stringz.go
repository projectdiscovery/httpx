package stringz

import (
	"strconv"
	"strings"
)

func TrimProtocol(URL string) string {
	URL = strings.TrimSpace(URL)
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
		v := strings.TrimSpace(v)
		if i, err := strconv.Atoi(v); err == nil {
			r = append(r, i)
		} else {
			return r, err
		}
	}

	return r, nil
}
