package httpx

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/transform"
)

// Credits: https://gist.github.com/zhangbaohe/c691e1da5bbdc7f41ca5

// Decodegbk converts GBK to UTF-8
func Decodegbk(s []byte) ([]byte, error) {
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := io.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}

// Decodebig5 converts BIG5 to UTF-8
func Decodebig5(s []byte) ([]byte, error) {
	I := bytes.NewReader(s)
	O := transform.NewReader(I, traditionalchinese.Big5.NewDecoder())
	d, e := io.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}

// Encodebig5 converts UTF-8 to BIG5
func Encodebig5(s []byte) ([]byte, error) {
	I := bytes.NewReader(s)
	O := transform.NewReader(I, traditionalchinese.Big5.NewEncoder())
	d, e := io.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func DecodeKorean(s []byte) ([]byte, error) {
	koreanDecoder := korean.EUCKR.NewDecoder()
	return koreanDecoder.Bytes(s)
}

// charsetParamIs reports whether contentType declares exactly this charset.
// contentType is already lowercased and unquoted.
func charsetParamIs(contentType, charset string) bool {
	for _, param := range strings.Split(contentType, ";") {
		name, value, found := strings.Cut(strings.TrimSpace(param), "=")
		if found && strings.TrimSpace(name) == "charset" && strings.TrimSpace(value) == charset {
			return true
		}
	}
	return false
}

// charsetParam returns the value of the charset parameter of contentType, or
// an empty string. contentType is already lowercased and unquoted.
func charsetParam(contentType string) string {
	for _, param := range strings.Split(contentType, ";") {
		name, value, found := strings.Cut(strings.TrimSpace(param), "=")
		if found && strings.TrimSpace(name) == "charset" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// decodeCharset converts data from the charset named by label to UTF-8. Data
// is returned as is when the label is empty, names UTF-8 or is not known.
func decodeCharset(data []byte, label string) ([]byte, error) {
	if label == "" {
		return data, nil
	}
	encoding, name := charset.Lookup(label)
	if encoding == nil || name == "utf-8" {
		return data, nil
	}
	return encoding.NewDecoder().Bytes(data)
}

// DecodeData converts a response body that is not UTF-8 to UTF-8, using the
// charset declared in the Content-Type header or in the page itself.
func DecodeData(data []byte, headers http.Header) ([]byte, error) {
	// A charset named by the header wins over the page. An unknown label, or
	// no Content-Type at all, falls through to the page.
	headerCharsetKnown := false
	if contentTypes, ok := headers["Content-Type"]; ok {
		contentType := strings.ToLower(strings.Join(contentTypes, ";"))
		// the charset parameter value can be a quoted string (charset="gbk")
		contentType = strings.NewReplacer(`"`, "", `'`, "").Replace(contentType)

		switch {
		case stringsutil.ContainsAny(contentType, "charset=gb2312", "charset=gbk"):
			return Decodegbk([]byte(data))
		case stringsutil.ContainsAny(contentType, "euc-kr"):
			return DecodeKorean(data)
		case charsetParamIs(contentType, "big5"):
			return Decodebig5(data)
		}

		// Any other charset declared in the header, such as iso-8859-1. A label
		// that is not a charset is ignored, and the page is looked at instead.
		if label := charsetParam(contentType); label != "" {
			if encoding, name := charset.Lookup(label); encoding != nil {
				headerCharsetKnown = true
				if name != "utf-8" {
					return encoding.NewDecoder().Bytes(data)
				}
			}
		}
	}
	if headerCharsetKnown {
		return data, nil
	}

	// Charset declared in a meta tag. This runs when the header is missing too.
	var match = reContentType.FindSubmatch(data)
	var mcontentType = ""
	if len(match) != 0 {
		for i, v := range match {
			if string(v) != "" && i != 0 {
				mcontentType = string(v)
			}
		}
		mcontentType = strings.ToLower(mcontentType)
	}
	switch {
	case stringsutil.ContainsAny(mcontentType, "gb2312", "gbk"):
		return Decodegbk(data)
	case stringsutil.ContainsAny(mcontentType, "big5", "Big5"):
		return Decodebig5(data)
	}
	return decodeCharset(data, mcontentType)
}
