package customextract

import "regexp"

var ExtractPresets = map[string]*regexp.Regexp{
	"url":  regexp.MustCompile("^(http(s)?:\\/\\/)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(:[0-9]{1,5})?[-a-zA-Z0-9()@:%_\\\\\\+\\.~#?&//=]*$"), //nolint
	"ipv4": regexp.MustCompile("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}"),                                                    //nolint
	"mail": regexp.MustCompile("^([A-Za-z0-9_\\-\\.\u4e00-\u9fa5])+\\@([A-Za-z0-9_\\-\\.])+\\.([A-Za-z]{2,8})$"),                                                        //nolint
}
