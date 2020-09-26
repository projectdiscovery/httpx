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
		if strings.Contains(contentType, "charset=GB2312") {
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
