package httpx

import (
	"regexp"
	"strings"
)

// Filter defines a generic filter interface to apply to responses
type Filter interface {
	Filter(response *Response) (bool, error)
}

// FilterString defines a filter of type string
type FilterString struct {
	Keywords []string
}

// Filter a response with strings filtering
func (f FilterString) Filter(response *Response) (bool, error) {
	for _, keyword := range f.Keywords {
		if strings.Contains(response.Raw, keyword) {
			return true, nil
		}
	}

	return false, nil
}

// FilterRegex defines a filter of type regex
type FilterRegex struct {
	Regexs []string
}

// Filter a response with regexes
func (f FilterRegex) Filter(response *Response) (bool, error) {
	for _, regex := range f.Regexs {
		matched, err := regexp.MatchString(regex, response.Raw)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}

// CustomCallback used in custom filters
type CustomCallback func(response *Response) (bool, error)

// FilterCustom defines a filter with callback functions applied
type FilterCustom struct {
	CallBacks []CustomCallback
}

// Filter a response with custom callbacks
func (f FilterCustom) Filter(response *Response) (bool, error) {
	for _, callback := range f.CallBacks {
		ok, err := callback(response)
		if ok && err == nil {
			return true, err
		}
	}

	return false, nil
}
