package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/classifier"
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

func TestPageTypeModelDefaultDiscovery(t *testing.T) {
	t.Chdir(t.TempDir())
	localPageModel(t, "model.json")
	r, err := New(&Options{KnowledgeBase: true})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	require.Equal(t, "error", r.classifyPage("", "<html></html>", 0)["PageType"])
}
