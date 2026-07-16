package runner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/projectdiscovery/httpx/common/stringz"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/stretchr/testify/require"
)

func TestWellKnownRecipes(t *testing.T) {
	for _, recipe := range WellKnownRecipes() {
		t.Run(recipe.Name, func(t *testing.T) {
			matched := false
			for path, fixture := range wellKnownFixtures {
				if !recipeMatchesPath(recipe, path) {
					continue
				}
				result := resultFromWellKnownFixture(path, fixture)
				if recipeMatches(recipe, result) {
					matched = true
					break
				}
			}
			require.True(t, matched, "recipe %q should match at least one fixture", recipe.Name)
		})
	}
}

func TestWellKnownRecipeSecurityTxtRejectsSoft404(t *testing.T) {
	recipe := WellKnownRecipes()[0]
	result := resultFromWellKnownFixture("/.well-known/security.txt", soft404Fixture)
	require.False(t, recipeMatches(recipe, result), "security.txt recipe should not match HTML soft-404 pages")
}

func TestWellKnownRecipeSecurityTxtRejectsMissingContact(t *testing.T) {
	recipe := WellKnownRecipes()[0]
	result := resultFromWellKnownFixture("/.well-known/security.txt", wellKnownFixture{
		statusCode:  http.StatusOK,
		contentType: "text/plain",
		body:        "Preferred-Languages: en\n",
	})
	require.False(t, recipeMatches(recipe, result), "security.txt recipe should require a Contact field")
}

func TestWellKnownRecipeAdsTxtRejectsInvalidBody(t *testing.T) {
	recipe := WellKnownRecipes()[4]
	result := resultFromWellKnownFixture("/ads.txt", wellKnownFixture{
		statusCode:  http.StatusOK,
		contentType: "text/plain",
		body:        "example.com, DIRECT\n",
	})
	require.False(t, recipeMatches(recipe, result), "ads.txt recipe should require an authorized digital seller entry")
}

func TestWellKnownRecipesHTTPProbe(t *testing.T) {
	ts := newWellKnownTestServer(t)
	defer ts.Close()

	recipe := WellKnownRecipes()[len(WellKnownRecipes())-1]
	for _, path := range strings.Split(recipe.Paths, ",") {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func recipeMatchesPath(recipe WellKnownRecipe, path string) bool {
	for _, recipePath := range strings.Split(recipe.Paths, ",") {
		if recipePath == path {
			return true
		}
	}
	return false
}

func recipeMatches(recipe WellKnownRecipe, result Result) bool {
	if recipe.MatchStatusCode != "" {
		codes, err := stringz.StringToSliceInt(recipe.MatchStatusCode)
		if err != nil || !sliceutil.Contains(codes, result.StatusCode) {
			return false
		}
	}
	if recipe.MatchCondition != "" && !evalDslExpr(result, recipe.MatchCondition) {
		return false
	}
	return true
}

func resultFromWellKnownFixture(path string, fixture wellKnownFixture) Result {
	url := "http://example.com" + path
	contentType := fixture.contentType
	if idx := strings.Index(contentType, ";"); idx >= 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	return Result{
		StatusCode:   fixture.statusCode,
		ContentType:  contentType,
		ResponseBody: fixture.body,
		URL:          url,
		str:          url,
	}
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
