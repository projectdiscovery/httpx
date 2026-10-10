package runner

import (
	"fmt"

	"github.com/happyhackingspace/dit"
)

// loadPageTypeModel checks that an explicit model can classify a page and form
// before runner initialization changes output files or creates resources. dit
// does not validate model structure and may panic during loading or inference.
func loadPageTypeModel(path string) (model *dit.Classifier, err error) {
	defer func() {
		if failure := recover(); failure != nil {
			model = nil
			err = fmt.Errorf("invalid page classification model: %v", failure)
		}
	}()
	model, err = dit.Load(path)
	if err != nil {
		return nil, err
	}
	// Two fields exercise the optional field classifier's sequence transitions.
	const probe = `<html><head><title>Example</title></head><body><form action="/login"><input type="text" name="username"><input type="password" name="password"><button type="submit">Login</button></form></body></html>`
	result, err := extractPageType(model, probe)
	if err != nil {
		return nil, fmt.Errorf("invalid page classification model: %w", err)
	}
	if result == nil || result.Type == "" || len(result.Forms) != 1 || result.Forms[0].Type == "" {
		return nil, fmt.Errorf("invalid page classification model: missing page or form prediction")
	}
	for _, label := range result.Forms[0].Fields {
		if label == "" {
			return nil, fmt.Errorf("invalid page classification model: missing field prediction")
		}
	}
	return model, nil
}

// extractPageType contains dependency panics at the same boundary as inference
// errors. A startup probe cannot exercise every input-dependent model feature.
func extractPageType(model *dit.Classifier, html string) (result *dit.PageResult, err error) {
	defer func() {
		if failure := recover(); failure != nil {
			result = nil
			err = fmt.Errorf("page classification failed: %v", failure)
		}
	}()
	return model.ExtractPageType(html)
}
