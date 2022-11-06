package customheader

import (
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
)

// CustomHeaders valid for all requests
type CustomHeaders []string

// String returns just a label
func (c *CustomHeaders) String() string {
	return "Custom Global Headers"
}

// Set a new global header
func (c *CustomHeaders) Set(value string) error {
	*c = append(*c, value)
	return nil
}

// Has checks if the list contains a header name
func (c *CustomHeaders) Has(header string) bool {
	for _, customHeader := range *c {
		if stringsutil.HasPrefixAny(strings.ToLower(customHeader), strings.ToLower(header)) {
			return true
		}
	}

	return false
}
