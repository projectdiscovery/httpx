package cache

import "strings"

var Separator = "-"

func MarshalAddresses(ips []string) []byte {
	return []byte(strings.Join(ips, Separator))
}

func UnmarshalAddresses(data []byte) []string {
	return strings.Split(string(data), Separator)
}
