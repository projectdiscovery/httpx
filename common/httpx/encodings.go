package httpx

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
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

// ExtractTitle from a response
func DecodeData(data []byte, headers http.Header) ([]byte, error) {
	// Non UTF-8
	if contentTypes, ok := headers["Content-Type"]; ok {
		contentType := strings.ToLower(strings.Join(contentTypes, ";"))

		switch {
		case stringsutil.ContainsAny(contentType, "charset=gb2312", "charset=gbk"):
			return Decodegbk([]byte(data))
		case stringsutil.ContainsAny(contentType, "euc-kr"):
			return DecodeKorean(data)
		}

		// Content-Type from head tag
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
		}
	}

	// return as is
	return data, nil
}
