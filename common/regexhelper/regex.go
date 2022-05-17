package regexhelper

import "regexp"

var (
	JarmHashRegex = regexp.MustCompile("(?m)0{62}")
)
