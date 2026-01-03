package runner

import (
	"fmt"
	"reflect"
	"strings"
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
		var items []string
		for i := 0; i < v.Len(); i++ {
			items = append(items, fmt.Sprintf("%v", v.Index(i).Interface()))
		}
		return escapeMarkdown(strings.Join(items, ", "))
	default:
		if v.CanInterface() {
			return escapeMarkdown(fmt.Sprintf("%v", v.Interface()))
		}
		return ""
	}
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"|", "\\|",
		"\n", " ",
	)
	return strings.TrimSpace(replacer.Replace(s))
}
