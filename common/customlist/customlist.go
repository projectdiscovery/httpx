package customlist

// CustomList for fastdialer
type CustomList []string

// String returns just a label
func (c *CustomList) String() string {
	return "Custom Global List"
}

// Set a new global header
func (c *CustomList) Set(value string) error {
	*c = append(*c, value)
	return nil
}
