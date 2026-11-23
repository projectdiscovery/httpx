package httpx

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestDecodeDataDeclaredCharset(t *testing.T) {
	shiftJIS, err := japanese.ShiftJIS.NewEncoder().Bytes([]byte("<title>日本語</title>"))
	require.NoError(t, err)
	gbk, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte("<title>中文</title>"))
	require.NoError(t, err)

	tests := []struct {
		name        string
		contentType string
		body        []byte
		want        string
	}{
		{
			name:        "iso-8859-1 in the Content-Type header",
			contentType: "text/html; charset=iso-8859-1",
			body:        []byte("<title>caf\xe9</title>"),
			want:        "<title>café</title>",
		},
		{
			name:        "windows-1252 in the Content-Type header",
			contentType: "text/html; charset=windows-1252",
			body:        []byte("<title>price \x80 5</title>"),
			want:        "<title>price € 5</title>",
		},
		{
			name:        "quoted charset and upper case",
			contentType: `text/html; charset="ISO-8859-1"`,
			body:        []byte("<title>na\xefve</title>"),
			want:        "<title>naïve</title>",
		},
		{
			name:        "shift_jis in the Content-Type header",
			contentType: "text/html; charset=shift_jis",
			body:        shiftJIS,
			want:        "<title>日本語</title>",
		},
		{
			name:        "charset only in a meta tag",
			contentType: "text/html",
			body:        []byte(`<meta charset="iso-8859-1"><title>caf` + "\xe9" + `</title>`),
			want:        `<meta charset="iso-8859-1"><title>café</title>`,
		},
		{
			name: "charset only in a meta tag and no Content-Type",
			body: []byte(`<meta charset="iso-8859-1"><title>caf` + "\xe9" + `</title>`),
			want: `<meta charset="iso-8859-1"><title>café</title>`,
		},
		{
			name:        "single quoted charset in the Content-Type header",
			contentType: "text/html; charset='iso-8859-1'",
			body:        []byte("<title>caf\xe9</title>"),
			want:        "<title>café</title>",
		},
		{
			name:        "unquoted charset in a meta tag",
			contentType: "text/html",
			body:        []byte(`<meta charset=iso-8859-1><title>caf` + "\xe9" + `</title>`),
			want:        `<meta charset=iso-8859-1><title>café</title>`,
		},
		{
			name:        "an unknown header charset falls back to the page",
			contentType: "text/html; charset=not-a-charset",
			body:        append([]byte(`<meta charset="iso-8859-1"><title>caf`), []byte("\xe9</title>")...),
			want:        `<meta charset="iso-8859-1"><title>café</title>`,
		},
		{
			name:        "the header wins over the page",
			contentType: "text/html; charset=utf-8",
			body:        []byte(`<meta charset="iso-8859-1"><title>café</title>`),
			want:        `<meta charset="iso-8859-1"><title>café</title>`,
		},
		{
			name:        "charset text outside a meta tag is ignored",
			contentType: "text/html",
			body:        []byte(`<script>var s = "charset=utf-8";</script><meta charset="iso-8859-1"><title>caf` + "\xe9" + `</title>`),
			want:        `<script>var s = "charset=utf-8";</script><meta charset="iso-8859-1"><title>café</title>`,
		},
		{
			name:        "charset in a meta http-equiv tag",
			contentType: "text/html",
			body:        []byte(`<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"><title>caf` + "\xe9" + `</title>`),
			want:        `<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"><title>café</title>`,
		},
		{
			name:        "gbk is still decoded",
			contentType: "text/html; charset=gbk",
			body:        gbk,
			want:        "<title>中文</title>",
		},
		{
			name:        "utf-8 is left alone",
			contentType: "text/html; charset=utf-8",
			body:        []byte("<title>café 日本語</title>"),
			want:        "<title>café 日本語</title>",
		},
		{
			name:        "no charset is left alone",
			contentType: "text/html",
			body:        []byte("<title>caf\xe9</title>"),
			want:        "<title>caf\xe9</title>",
		},
		{
			name:        "unknown charset is left alone",
			contentType: "text/html; charset=not-a-charset",
			body:        []byte("<title>caf\xe9</title>"),
			want:        "<title>caf\xe9</title>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.contentType != "" {
				headers.Set("Content-Type", tt.contentType)
			}
			got, err := DecodeData(tt.body, headers)
			require.NoError(t, err)
			require.Equal(t, tt.want, string(got))
		})
	}
}

func TestExtractTitleDeclaredCharset(t *testing.T) {
	headers := http.Header{"Content-Type": []string{"text/html; charset=iso-8859-1"}}
	data, err := DecodeData([]byte("<html><head><title>caf\xe9</title></head></html>"), headers)
	require.NoError(t, err)

	require.Equal(t, "café", ExtractTitle(&Response{Data: data, Raw: string(data)}))
}
