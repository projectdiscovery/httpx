package inputformats

import (
	"io"

	"github.com/pkg/errors"
	"github.com/seh-msft/burpxml"
)

// BurpFormat is a Burp Suite XML file parser
type BurpFormat struct{}

// NewBurpFormat creates a new Burp XML file parser
func NewBurpFormat() *BurpFormat {
	return &BurpFormat{}
}

var _ Format = &BurpFormat{}

// Name returns the name of the format
func (b *BurpFormat) Name() string {
	return "burp"
}

// Parse parses the Burp XML input and calls the provided callback
// function for each URL it discovers.
func (b *BurpFormat) Parse(input io.Reader, callback func(url string) bool) error {
	items, err := burpxml.Parse(input, true)
	if err != nil {
		return errors.Wrap(err, "could not parse burp xml")
	}

	for _, item := range items.Items {
		if item.Url == "" {
			continue
		}
		if !callback(item.Url) {
			break
		}
	}
	return nil
}
