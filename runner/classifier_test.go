package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit"
	"github.com/happyhackingspace/dit/classifier"
	"github.com/happyhackingspace/dit/crf"
	"github.com/stretchr/testify/require"
)

// localPageModel creates a small, valid model without downloading training data
// or the production model. One class makes the expected prediction deterministic.
func localPageModel(t *testing.T, path string) {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader("<html><body><form><input name='username'></form>Example page</body></html>"))
	require.NoError(t, err)
	config := classifier.DefaultPageTypeTrainConfig()
	config.MaxIter = 1
	formConfig := classifier.DefaultFormTypeTrainConfig()
	formConfig.MaxIter = 1
	model := &classifier.FormFieldClassifier{
		FormModel: classifier.TrainFormType([]*goquery.Selection{doc.Find("form")}, []string{"login"}, formConfig),
		PageModel: classifier.TrainPageType(
			[]*goquery.Document{doc}, [][]classifier.ClassifyResult{nil},
			[]string{"https://example.com"}, []string{"error"}, config,
		),
	}
	require.NoError(t, model.SaveModel(path))
}

func TestLocalPageTypeModel(t *testing.T) {
	modelPath := filepath.Join(t.TempDir(), "custom model.json")
	localPageModel(t, modelPath)

	// A broken auto-discovered model must not override the explicit model path.
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("model.json", []byte("invalid JSON"), 0600))

	for _, tc := range []struct {
		name    string
		options Options
	}{
		{name: "knowledge base", options: Options{KnowledgeBase: true}},
		{name: "page type filter", options: Options{OutputFilterPageType: []string{"error"}}},
		{name: "deprecated error page filter", options: Options{OutputFilterErrorPage: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := tc.options
			options.PageTypeModel = modelPath
			r, err := New(&options)
			require.NoError(t, err)
			t.Cleanup(r.Close)
			kb := r.classifyPage("", "<html><body><form><input name='username'></form></body></html>", 0)
			require.Equal(t, "error", kb["PageType"])
			require.NotEmpty(t, kb["Forms"])
		})
	}
}

func TestLocalPageTypeModelErrors(t *testing.T) {
	// A valid auto-discovered model must not hide an invalid explicit path.
	t.Chdir(t.TempDir())
	localPageModel(t, "model.json")
	require.NoError(t, os.WriteFile("invalid.json", []byte("invalid JSON"), 0600))

	for _, path := range []string{"missing.json", "invalid.json"} {
		t.Run(path, func(t *testing.T) {
			r, err := New(&Options{KnowledgeBase: true, PageTypeModel: path})
			require.ErrorContains(t, err, "could not initialize page classifier")
			require.Nil(t, r)
		})
	}
}

func TestPageTypeModelDoesNotEnableClassification(t *testing.T) {
	r, err := New(&Options{PageTypeModel: filepath.Join(t.TempDir(), "missing.json")})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	require.Nil(t, r.ditClassifier)
	require.NotContains(t, r.classifyPage("", "<html></html>", 0), "PageType")
}

func TestLocalPageTypeModelErrorsPreserveResponseIndexes(t *testing.T) {
	for _, name := range []string{"missing", "invalid JSON", "{}", "null", `{"form_model":{},"page_model":{}}`} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			modelPath := filepath.Join(dir, "model.json")
			if name != "missing" {
				require.NoError(t, os.WriteFile(modelPath, []byte(name), 0600))
			}
			indexes := []string{
				filepath.Join(dir, "response", "index.txt"),
				filepath.Join(dir, "screenshot", "index_screenshot.txt"),
			}
			for _, path := range indexes {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
				require.NoError(t, os.WriteFile(path, []byte("previous scan results"), 0600))
			}

			r, err := New(&Options{KnowledgeBase: true, PageTypeModel: modelPath, StoreResponseDir: dir})
			require.ErrorContains(t, err, "could not initialize page classifier")
			require.Nil(t, r)
			for _, path := range indexes {
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, "previous scan results", string(data))
			}
		})
	}
}

func TestPageTypeModelDefaultDiscovery(t *testing.T) {
	t.Chdir(t.TempDir())
	localPageModel(t, "model.json")
	r, err := New(&Options{KnowledgeBase: true})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	require.Equal(t, "error", r.classifyPage("", "<html></html>", 0)["PageType"])
}

// TestLocalPageTypeModelMalformedStructures exercises failures beyond JSON parsing.
func TestLocalPageTypeModelMalformedStructures(t *testing.T) {
	validPath := filepath.Join(t.TempDir(), "valid.json")
	localPageModel(t, validPath)
	valid, err := os.ReadFile(validPath)
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		mutate func(*classifier.UnifiedModel)
	}{
		{"missing form", func(m *classifier.UnifiedModel) { m.FormModel = nil }},
		{"missing page", func(m *classifier.UnifiedModel) { m.PageModel = nil }},
		{"empty form", func(m *classifier.UnifiedModel) { m.FormModel = &classifier.FormTypeModel{} }},
		{"empty page", func(m *classifier.UnifiedModel) { m.PageModel = &classifier.PageTypeModel{} }},
		{"missing page classes", func(m *classifier.UnifiedModel) { m.PageModel.Classes = nil }},
		{"missing form coefficients", func(m *classifier.UnifiedModel) { m.FormModel.Coef = nil }},
		{"missing page intercepts", func(m *classifier.UnifiedModel) { m.PageModel.Intercept = nil }},
		{"missing vectorizer", func(m *classifier.UnifiedModel) {
			p := &m.PageModel.Pipelines[0]
			p.DictVec, p.CountVec, p.TfidfVec = nil, nil, nil
		}},
		{"empty field model", func(m *classifier.UnifiedModel) { m.FieldModel = &crf.Model{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var model classifier.UnifiedModel
			require.NoError(t, json.Unmarshal(valid, &model))
			tc.mutate(&model)
			data, err := json.Marshal(model)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "model.json")
			require.NoError(t, os.WriteFile(path, data, 0600))
			require.NotPanics(t, func() {
				r, err := New(&Options{KnowledgeBase: true, PageTypeModel: path})
				if r != nil {
					t.Cleanup(r.Close)
				}
				require.ErrorContains(t, err, "could not initialize page classifier")
				require.Nil(t, r)
			})
		})
	}
}

// TestClassifyPageMalformedModelContainsPanic covers failures reached only at inference.
func TestClassifyPageMalformedModelContainsPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"form_model":{},"page_model":{}}`), 0600))
	model, err := dit.Load(path)
	require.NoError(t, err)
	r := &Runner{ditClassifier: model}
	require.NotPanics(t, func() {
		require.Equal(t, map[string]any{"pHash": uint64(42)}, r.classifyPage("", "<html></html>", 42))
	})
}

// TestClassifyPageLatentModelFailure covers a corrupt feature not used by the startup probe.
func TestClassifyPageLatentModelFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.json")
	localPageModel(t, path)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var model classifier.UnifiedModel
	require.NoError(t, json.Unmarshal(data, &model))
	for _, pipeline := range model.PageModel.Pipelines {
		if pipeline.Name == "page title" {
			pipeline.TfidfVec.CountVec.Vocabulary["corruptfeature"] = -1
		}
	}
	data, err = json.Marshal(model)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	loaded, err := loadPageTypeModel(path)
	require.NoError(t, err)
	const html = "<html><head><title>corruptfeature</title></head></html>"
	require.Panics(t, func() { _, _ = loaded.ExtractPageType(html) })
	r := &Runner{ditClassifier: loaded}
	require.NotPanics(t, func() {
		require.Equal(t, map[string]any{"pHash": uint64(42)}, r.classifyPage("", html, 42))
	})
	// A failure does not mutate the shared classifier or disable later results.
	require.Equal(t, "error", r.classifyPage("", "<html></html>", 0)["PageType"])
}

// TestLocalPageTypeModelWithFields accepts a valid optional field classifier.
func TestLocalPageTypeModelWithFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.json")
	localPageModel(t, path)
	model, err := classifier.LoadClassifier(path)
	require.NoError(t, err)
	fieldModel := crf.NewModel()
	fieldModel.Labels.Add("other")
	fieldModel.NumLabels = 1
	fieldModel.Weights = []float64{0}
	model.FieldModel = &classifier.FieldTypeModel{CRF: fieldModel}
	require.NoError(t, model.SaveModel(path))
	loaded, err := loadPageTypeModel(path)
	require.NoError(t, err)
	result, err := extractPageType(loaded, `<html><form><input name="one"><input name="two"></form></html>`)
	require.NoError(t, err)
	require.Len(t, result.Forms, 1)
	require.Equal(t, map[string]string{"one": "other", "two": "other"}, result.Forms[0].Fields)
}
