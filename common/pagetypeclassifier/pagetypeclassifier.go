package pagetypeclassifier

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	htmltomarkdown "github.com/JohannesKaufmann/html-to-markdown/v2"
	"github.com/microcosm-cc/bluemonday"
	"github.com/projectdiscovery/utils/ml/naive_bayes"
)

//go:embed clf.gob
var classifierData []byte

type PageTypeClassifier struct {
	classifier *naive_bayes.NaiveBayesClassifier
}

func New() (*PageTypeClassifier, error) {
	classifier, err := naive_bayes.NewClassifierFromFileData(classifierData)
	if err != nil {
		return nil, err
	}
	return &PageTypeClassifier{classifier: classifier}, nil
}

func (n *PageTypeClassifier) Classify(html string) string {
	text, err := htmlToText(html)
	if err != nil || text == "" {
		return "other"
	}
	return n.classifier.Classify(text)
}

var (
	// sanitizerPolicy is an aggressive bluemonday policy that strips most HTML
	// to reduce nesting depth and prevent parser stack overflow
	sanitizerPolicy     *bluemonday.Policy
	sanitizerPolicyOnce sync.Once
)

// getSanitizerPolicy returns an ultra-aggressive HTML sanitizer policy that strips
// almost all elements to minimize nesting depth and prevent parser stack overflow.
func getSanitizerPolicy() *bluemonday.Policy {
	sanitizerPolicyOnce.Do(func() {
		p := bluemonday.NewPolicy()
		// Ultra-aggressive policy: Allow only the most basic text elements
		// to minimize nesting and reduce parser stack depth
		p.AllowElements("p", "br", "h1", "h2", "h3", "h4", "h5", "h6")
		p.AllowElements("strong", "em", "b", "i")
		// Remove div, span, ul, ol, li as they can create deep nesting
		// No attributes allowed to prevent style-based nesting issues
		sanitizerPolicy = p
	})
	return sanitizerPolicy
}

// htmlToText safely converts HTML to text with multiple fallback strategies.
// The 512 node limit in golang.org/x/net/html is hardcoded and cannot be increased.
// Strategy:
// 1. Length limit the input HTML to prevent massive documents
// 2. Sanitize HTML aggressively with bluemonday to reduce nesting
// 3. Convert sanitized HTML to markdown with panic recovery
// 4. If conversion fails, fallback to plain text extraction
func htmlToText(html string) (text string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("html parser panic: %v", r)
			text = ""
		}
	}()

	// Limit input size to prevent processing extremely large HTML documents
	const maxHTMLSize = 1024 * 1024 // 1MB limit
	if len(html) > maxHTMLSize {
		html = html[:maxHTMLSize]
	}

	// First, sanitize HTML with ultra-aggressive bluemonday policy
	sanitizedHTML := getSanitizerPolicy().Sanitize(html)

	// If sanitization failed or produced empty result, try plain text fallback
	if sanitizedHTML == "" {
		return extractPlainText(html), nil
	}

	// Convert sanitized HTML to markdown
	text, err = htmltomarkdown.ConvertString(sanitizedHTML)
	if err != nil {
		// If markdown conversion fails, fallback to plain text extraction
		return extractPlainText(sanitizedHTML), nil
	}
	
	if text == "" {
		// If result is empty, try plain text fallback
		return extractPlainText(sanitizedHTML), nil
	}

	return text, nil
}

// extractPlainText is a simple fallback that extracts text content without HTML parsing
// This is used when the HTML parser fails due to complexity or nesting depth
func extractPlainText(html string) string {
	// Simple regex-based text extraction as fallback
	// Remove script and style tags first
	text := html
	
	// Remove script tags and content
	for {
		start := strings.Index(text, "<script")
		if start == -1 {
			break
		}
		end := strings.Index(text[start:], "</script>")
		if end == -1 {
			text = text[:start]
			break
		}
		text = text[:start] + text[start+end+9:]
	}
	
	// Remove style tags and content
	for {
		start := strings.Index(text, "<style")
		if start == -1 {
			break
		}
		end := strings.Index(text[start:], "</style>")
		if end == -1 {
			text = text[:start]
			break
		}
		text = text[:start] + text[start+end+8:]
	}
	
	// Simple HTML tag removal (not perfect but safe)
	result := ""
	inTag := false
	for _, char := range text {
		if char == '<' {
			inTag = true
		} else if char == '>' {
			inTag = false
			result += " " // Replace tags with spaces
		} else if !inTag {
			result += string(char)
		}
	}
	
	// Clean up multiple spaces
	words := strings.Fields(result)
	return strings.Join(words, " ")
}
