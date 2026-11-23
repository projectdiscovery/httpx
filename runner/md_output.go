package runner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

func (r Result) MarkdownHeader() string { //nolint
	var headers []string

	t := reflect.TypeOf(r)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("md")
		if tag == "" || tag == "-" {
			continue
		}
		headers = append(headers, tag)
	}

	var b strings.Builder
	b.WriteString("|")
	for _, h := range headers {
		fmt.Fprintf(&b, " %s |", h)
	}
	b.WriteString("\n")

	b.WriteString("|")
	for range headers {
		b.WriteString("---|")
	}
	b.WriteString("\n")

	return b.String()
}

func (r Result) MarkdownRow(scanopts *ScanOptions) string { //nolint
	var values []string

	v := reflect.ValueOf(r)
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("md")
		if tag == "" || tag == "-" {
			continue
		}

		fieldValue := v.Field(i)
		values = append(values, formatMarkdownValue(fieldValue))
	}

	var b strings.Builder
	b.WriteString("|")
	for _, val := range values {
		fmt.Fprintf(&b, " %s |", val)
	}
	b.WriteString("\n")

	return b.String()
}

func formatMarkdownValue(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return escapeMarkdown(v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", v.Int())
	case reflect.Bool:
		return fmt.Sprintf("%t", v.Bool())
	case reflect.Slice:
		if v.Len() == 0 {
			return ""
		}
		if b, ok := v.Interface().([]byte); ok {
			return base64.StdEncoding.EncodeToString(b)
		}
		if k := v.Type().Elem().Kind(); k == reflect.String || k == reflect.Int {
			var items []string
			for i := 0; i < v.Len(); i++ {
				items = append(items, fmt.Sprintf("%v", v.Index(i).Interface()))
			}
			return escapeMarkdown(strings.Join(items, ", "))
		}
	case reflect.Pointer:
		if v.IsNil() {
			return ""
		}
	}
	if !v.CanInterface() {
		return ""
	}
	if t, ok := v.Interface().(time.Time); ok {
		return t.Format(time.RFC3339Nano)
	}
	// Structured values render as in the JSON output; %v would print Go syntax.
	b, err := json.Marshal(v.Interface())
	if err != nil {
		return ""
	}
	return escapeMarkdown(string(b))
}

func escapeMarkdown(s string) string {
	// Escape backslashes as well as pipes so a literal "\|" keeps its backslash,
	// and flatten every line ending so one result stays on one table row.
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"|", "\\|",
		"\r\n", " ",
		"\r", " ",
		"\n", " ",
	)
	return strings.TrimSpace(replacer.Replace(s))
}
