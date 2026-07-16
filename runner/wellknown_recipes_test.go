package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var httpxBinary string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "httpx-recipes-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	httpxBinary = filepath.Join(tmp, "httpx")
	moduleRoot, err := filepath.Abs("..")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve module root: %v\n", err)
		_ = os.RemoveAll(tmp)
		os.Exit(1)
	}

	build := exec.Command("go", "build", "-o", httpxBinary, "./cmd/httpx")
	build.Dir = moduleRoot
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build httpx: %v\n%s\n", err, out)
		_ = os.RemoveAll(tmp)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

func TestWellKnownRecipes(t *testing.T) {
	ts := newWellKnownTestServer(t)
	defer ts.Close()

	for _, recipe := range WellKnownRecipes() {
		t.Run(recipe.Name, func(t *testing.T) {
			results, err := runRecipe(ts.URL, recipe)
			require.NoError(t, err)
			require.NotEmpty(t, results, "recipe %q should match at least one response", recipe.Name)
		})
	}
}

func TestWellKnownRecipeSecurityTxtRejectsSoft404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", soft404Fixture.contentType)
		w.WriteHeader(soft404Fixture.statusCode)
		_, _ = w.Write([]byte(soft404Fixture.body))
	}))
	defer ts.Close()

	recipe := WellKnownRecipes()[0]
	results, err := runRecipe(ts.URL, recipe)
	require.NoError(t, err)
	require.Empty(t, results, "security.txt recipe should not match HTML soft-404 pages")
}

func TestWellKnownRecipeSecurityTxtRejectsMissingContact(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Preferred-Languages: en\n"))
	}))
	defer ts.Close()

	recipe := WellKnownRecipes()[0]
	results, err := runRecipe(ts.URL, recipe)
	require.NoError(t, err)
	require.Empty(t, results, "security.txt recipe should require a Contact field")
}

func TestWellKnownRecipeAdsTxtRejectsInvalidBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("example.com, DIRECT\n"))
	}))
	defer ts.Close()

	recipe := WellKnownRecipes()[4]
	results, err := runRecipe(ts.URL, recipe)
	require.NoError(t, err)
	require.Empty(t, results, "ads.txt recipe should require an authorized digital seller entry")
}

func runRecipe(target string, recipe WellKnownRecipe) ([]string, error) {
	args := append([]string{"-silent", "-path", recipe.Paths}, recipe.Args...)
	cmd := exec.Command(httpxBinary, args...)
	cmd.Stdin = strings.NewReader(target + "\n")

	data, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(data)))
	}

	var results []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			results = append(results, line)
		}
	}
	return results, nil
}

func newWellKnownTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture, ok := wellKnownFixtures[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", fixture.contentType)
		w.WriteHeader(fixture.statusCode)
		_, _ = w.Write([]byte(fixture.body))
	}))
}
