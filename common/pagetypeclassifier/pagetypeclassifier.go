package pagetypeclassifier

import (
	_ "embed"

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

// htmlToText safely converts HTML to text and protects against panics from Go's HTML parser.
func htmlToText(html string) (string, error) {
	return htmltomarkdown.ConvertString(html)
}
