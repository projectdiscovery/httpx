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

func New() *PageTypeClassifier {
	classifier, err := naive_bayes.NewClassifierFromFileData(classifierData)
	if err != nil {
		panic(err)
	}
	return &PageTypeClassifier{classifier: classifier}
}

func (n *PageTypeClassifier) Classify(html string) string {
	text := htmlToText(html)
	if text == "" {
		return "other"
	}
	return n.classifier.Classify(text)
}

// htmlToText safely converts HTML to text and protects against panics from Go's HTML parser.
func htmlToText(html string) (text string) {
	defer func() {
		if r := recover(); r != nil {
			// Optionally log this event, e.g., log.Printf("Recovered in htmlToText: %v", r)
			text = ""
		}
	}()
	var err error
	text, err = htmltomarkdown.ConvertString(html)
	if err != nil {
		text = ""
	}
	return
}
