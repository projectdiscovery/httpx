package pagetypeclassifier

import (
	_ "embed"
	"sync"

	"github.com/microcosm-cc/bluemonday"
	htmltomarkdown "github.com/JohannesKaufmann/html-to-markdown/v2"
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

// getSanitizerPolicy returns an aggressive HTML sanitizer policy that strips
// most elements to reduce nesting depth and prevent parser stack overflow.
func getSanitizerPolicy() *bluemonday.Policy {
	sanitizerPolicyOnce.Do(func() {
		p := bluemonday.NewPolicy()
		// Allow only basic text elements with minimal nesting
		// This aggressive policy helps reduce nesting depth significantly
		p.AllowElements("p", "br", "div", "span", "h1", "h2", "h3", "h4", "h5", "h6")
		p.AllowElements("strong", "em", "b", "i", "u")
		p.AllowElements("ul", "ol", "li")
		p.AllowElements("blockquote", "pre", "code")
		// Allow basic attributes but no style (which can cause nesting issues)
		p.AllowStandardAttributes()
		sanitizerPolicy = p
	})
	return sanitizerPolicy
}

// htmlToText safely converts HTML to text and protects against panics from Go's HTML parser.
// The 512 node limit in golang.org/x/net/html is hardcoded and cannot be increased.
// Strategy:
// 1. Always sanitize HTML with bluemonday first to remove useless elements and reduce nesting
// 2. Convert sanitized HTML to markdown
// 3. If conversion panics, recover and return empty string
func htmlToText(html string) (string, error) {
	defer func() {
		if r := recover(); r != nil {
			// If anything panics, we'll return empty string
		}
	}()
	
	// First, sanitize HTML with bluemonday to strip useless elements and reduce nesting
	sanitizedHTML := getSanitizerPolicy().Sanitize(html)
	
	// If sanitization failed or produced empty result, return empty
	if sanitizedHTML == "" {
		return "", nil
	}
	
	// Convert sanitized HTML to markdown
	result, err := htmltomarkdown.ConvertString(sanitizedHTML)
	if err != nil || result == "" {
		return "", nil
	}
	
	return result, nil
}
