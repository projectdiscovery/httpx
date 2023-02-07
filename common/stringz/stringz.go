package stringz

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/spaolacci/murmur3"
)

// TrimProtocol removes the HTTP scheme from an URI
func TrimProtocol(targetURL string, addDefaultPort bool) string {
	URL := strings.TrimSpace(targetURL)
	if strings.HasPrefix(strings.ToLower(URL), "http://") || strings.HasPrefix(strings.ToLower(URL), "https://") {
		if addDefaultPort {
			URL = AddURLDefaultPort(URL)
			URL = URL[strings.Index(URL, "//")+2:]
		}
	}

	return URL
}

// StringToSliceInt converts string to slice of ints
func StringToSliceInt(s string) ([]int, error) {
	var r []int
	if s == "" {
		return r, nil
	}
	for _, v := range strings.Split(s, ",") {
		vTrim := strings.TrimSpace(v)
		if i, err := strconv.Atoi(vTrim); err == nil {
			r = append(r, i)
		} else {
			return r, err
		}
	}

	return r, nil
}

// StringToSliceUInt converts string to slice of ints
func StringToSliceUInt32(s string) ([]uint32, error) {
	var r []uint32
	if s == "" {
		return r, nil
	}
	for _, v := range strings.Split(s, ",") {
		vTrim := strings.TrimSpace(v)
		if i, err := strconv.ParseUint(vTrim, 10, 64); err == nil {
			r = append(r, uint32(i))
		} else {
			return r, err
		}
	}

	return r, nil
}

// SplitByCharAndTrimSpace splits string by a character and remove spaces
func SplitByCharAndTrimSpace(s, splitchar string) (result []string) {
	for _, token := range strings.Split(s, splitchar) {
		result = append(result, strings.TrimSpace(token))
	}
	return
}

// AddURLDefaultPort add url default port (80/443) from an URI
// eg:
// http://foo.com -> http://foo.com:80
// https://foo.com -> https://foo.com:443
func AddURLDefaultPort(rawURL string) string {
	u, err := urlutil.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.String()
}

// RemoveURLDefaultPort remove url default port (80/443) from an URI
// eg:
// http://foo.com:80 -> http://foo.com
// https://foo.com:443 -> https://foo.com
func RemoveURLDefaultPort(rawURL string) string {
	u, err := urlutil.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	if u.Scheme == urlutil.HTTP && u.Port() == "80" || u.Scheme == urlutil.HTTPS && u.Port() == "443" {
		u.TrimPort()
	}
	return u.String()
}

func GetInvalidURI(rawURL string) (bool, string) {
	if _, err := url.Parse(rawURL); err != nil {
		if u, err := urlutil.Parse(rawURL); err == nil {
			return true, u.GetRelativePath()
		}
	}
	return false, ""
}

func isContentTypeImage(data []byte) bool {
	contentType := http.DetectContentType(data)
	return stringsutil.HasPrefixAny(contentType, "image/")
}

func murmurhash(data []byte) int32 {
	stdBase64 := base64.StdEncoding.EncodeToString(data)
	stdBase64 = InsertInto(stdBase64, 76, '\n')
	hasher := murmur3.New32WithSeed(0)
	hasher.Write([]byte(stdBase64))
	return int32(hasher.Sum32())
}

func FaviconHash(data []byte) (int32, error) {
	if isContentTypeImage(data) {
		return murmurhash(data), nil
	}

	return 0, errors.New("content type is not image")
}

func InsertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	buffer.WriteRune(sep)
	return buffer.String()
}

// Base64 returns base64 of given byte array
func Base64(bin []byte) string {
	return base64.StdEncoding.EncodeToString(bin)
}
