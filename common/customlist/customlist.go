package customlist

import "github.com/projectdiscovery/httpx/common/fileutil"

// CustomList for fastdialer
type CustomList []string

// String returns just a label
func (c *CustomList) String() string {
	return "Custom Global List"
}

// Set a new global header
func (c *CustomList) Set(value string) error {
	values := fileutil.LoadCidrsFromSliceOrFile(value, ",")
	*c = append(*c, values...)
	return nil
}
