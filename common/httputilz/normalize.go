package httputilz

import "regexp"

var (
	normalizeSpacesRegex = regexp.MustCompile(`\s+`)
)

func NormalizeSpaces(data string) string {
	return normalizeSpacesRegex.ReplaceAllString(data, " ")
}
