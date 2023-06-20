package errorpageclassifier

import (
	_ "embed"
	"fmt"
	"math/rand"
	"strings"

	"github.com/jaytaylor/html2text"
)

const (
	modelPath      = "clf.gob"
	threshold      = 1.1
	testPercentage = 0.2
)

var categories = []string{"error", "nonerror"}

type Document struct {
	Class string
	Text  string
}

//go:embed dataset.txt
var dataset string

//go:embed clf.gob
var classifierData []byte

type ErrorPageClassifier struct {
	classifier *Classifier
}

func New() *ErrorPageClassifier {
	classifier, err := NewClassifierFromFileData(classifierData)
	if err != nil {
		panic(err)
	}
	return &ErrorPageClassifier{classifier: classifier}
}

func (n *ErrorPageClassifier) Classify(html string) string {
	text, err := htmlToText(html)
	if err != nil {
		panic(err)
	}

	if text == "" {
		return "other"
	}
	cls := n.classifier.Classify(text)
	return cls
}

func (epc *ErrorPageClassifier) Evaluate() {
	train, test := trainTestSplit()
	fmt.Println("no of docs in TRAIN dataset:", len(train))
	fmt.Println("no of docs in TEST dataset:", len(test))

	fmt.Println("Evaluating classifier on test set:")
	actualTest, predictedTest := epc.testClf(test)
	confusionMatrixTest := NewConfusionMatrix(actualTest, predictedTest, []string{"error", "nonerror"})
	confusionMatrixTest.PrintConfusionMatrix()
	confusionMatrixTest.PrintClassificationReport()

	fmt.Println("Evaluating classifier on the first 100 docs in the train set:")
	actualValidate, predictedValidate := epc.validateClf(train[0:100])
	confusionMatrixValidate := NewConfusionMatrix(actualValidate, predictedValidate, []string{"error", "nonerror"})
	confusionMatrixValidate.PrintConfusionMatrix()
	confusionMatrixValidate.PrintClassificationReport()
}

func (epc *ErrorPageClassifier) testClf(test []Document) ([]string, []string) {
	actual := []string{}
	predicted := []string{}

	for _, doc := range test {
		class := epc.classifier.Classify(doc.Text)
		actual = append(actual, doc.Class)
		predicted = append(predicted, class)
	}
	return actual, predicted
}

func (epc *ErrorPageClassifier) validateClf(validation []Document) ([]string, []string) {
	actual := []string{}
	predicted := []string{}

	for _, doc := range validation {
		actual = append(actual, doc.Class)
		sentiment := epc.classifier.Classify(doc.Text)
		predicted = append(predicted, sentiment)
	}
	return actual, predicted
}

func TrainAndSave() {
	train, test := trainTestSplit()
	clf := NewClassifier(categories, threshold)

	fmt.Println("no of docs in TRAIN dataset:", len(train))
	fmt.Println("no of docs in TEST dataset:", len(test))

	for _, doc := range train {
		clf.Train(doc.Class, doc.Text)
	}

	err := clf.SaveClassifierToFile(modelPath)
	if err != nil {
		panic(err)
	}
}

func trainTestSplit() (train, test []Document) {
	data := strings.Split(dataset, "\n")
	for _, line := range data {
		s := strings.Split(line, "||")
		doc, sentiment := s[0], s[1]

		if rand.Float64() > testPercentage {
			train = append(train, Document{sentiment, doc})
		} else {
			test = append(test, Document{sentiment, doc})
		}
	}
	return train, test
}

func htmlToText(html string) (string, error) {
	text, err := html2text.FromString(html, html2text.Options{TextOnly: true})
	if err != nil {
		return "", err
	}
	return text, nil
}
