// TODO: This package should be abstracted out to projectdiscovery/utils
// so it can be shared between httpx, nuclei, and other tools.
package inputformats

import (
	"io"
	"strings"
)

// Format is an interface implemented by all input formats
type Format interface {
	// Name returns the name of the format
	Name() string
	// Parse parses the input and calls the provided callback
	// function for each URL it discovers.
	Parse(input io.Reader, callback func(url string) bool) error
}

// Supported formats
var formats = []Format{
	NewBurpFormat(),
}

// GetFormat returns the format by name
func GetFormat(name string) Format {
	for _, f := range formats {
		if strings.EqualFold(f.Name(), name) {
			return f
		}
	}
	return nil
}

// SupportedFormats returns a comma-separated list of supported format names
func SupportedFormats() string {
	var names []string
	for _, f := range formats {
		names = append(names, f.Name())
	}
	return strings.Join(names, ", ")
}
