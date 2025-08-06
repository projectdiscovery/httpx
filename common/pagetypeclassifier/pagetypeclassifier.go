package pagetypeclassifier

import (
	_ "embed"

	"github.com/k3a/html2text"
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

func htmlToText(html string) string {
	return html2text.HTML2Text(html)
}
