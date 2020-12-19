package httpx

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// ExtractTitle from a response
func ExtractTitle(r *Response) (title string) {
	var re = regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
	for _, match := range re.FindAllString(r.Raw, -1) {
		title = html.UnescapeString(trimTitleTags(match))
		break
	}

	// Non UTF-8
	if contentTypes, ok := r.Headers["Content-Type"]; ok {
		contentType := strings.Join(contentTypes, ";")

		// special cases
		if strings.Contains(strings.ToLower(contentType), "charset=gb2312") ||
			strings.Contains(strings.ToLower(contentType), "charset=gbk") {
			titleUtf8, err := Decodegbk([]byte(title))
			if err != nil {
				return
			}

			return string(titleUtf8)
		}

		// Content-Type from head tag
		re = regexp.MustCompile(`(?im)\s*charset="(.*?)"|charset=(.*?)"\s*`)
		var match = re.FindSubmatch(r.Data)
		var mcontentType = ""
		if len(match) != 0 {
			for i, v := range match {
				if string(v) != "" && i != 0 {
					mcontentType = string(v)
				}
			}
			mcontentType = strings.ToLower(mcontentType)
		}
		if strings.Contains(mcontentType, "gb2312") || strings.Contains(mcontentType, "gbk") {
			titleUtf8, err := Decodegbk([]byte(title))
			if err != nil {
				return
			}

			return string(titleUtf8)
		}
	}

	return
}

func trimTitleTags(title string) string {
	// trim <title>*</title>
	titleBegin := strings.Index(title, ">")
	titleEnd := strings.Index(title, "</")
	return title[titleBegin+1 : titleEnd]
}
