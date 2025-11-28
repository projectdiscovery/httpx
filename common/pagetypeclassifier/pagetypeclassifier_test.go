package pagetypeclassifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPageTypeClassifier(t *testing.T) {
	t.Run("test creation of new PageTypeClassifier", func(t *testing.T) {
		epc, err := New()
		require.NoError(t, err)
		require.NotNil(t, epc)
	})

	t.Run("test classification non error page text", func(t *testing.T) {
		epc, err := New()
		require.NoError(t, err)
		require.NotNil(t, epc)
		require.Equal(t, "nonerror", epc.Classify(`<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<title>Terms of Service</title>
		</head>
		<body>
			<h1>Welcome to our Terms of Service page.</h1>
			<p>Understand our conditions for providing services.</p>
		</body>
		</html>
		`))
	})

	t.Run("test classification on error page text", func(t *testing.T) {
		epc, err := New()
		require.NoError(t, err)
		require.NotNil(t, epc)
		require.Equal(t, "error", epc.Classify(`<!DOCTYPE html>
		<html>
		<head>
			<title>Error 403: Forbidden</title>
			<style>
				.error-message {
					text-align: center;
					color: #333;
				}
			</style>
		</head>
		<body>
			<div class="error-message">
				<h1>Error 403: Forbidden</h1>
				<p>Sorry you don't have access rights to this page.</p>
			</div>
		</body>
		</html>
		`))
	})

	t.Run("test panic recovery with deeply nested HTML", func(t *testing.T) {
		epc, err := New()
		require.NoError(t, err)
		require.NotNil(t, epc)

		// Generate deeply nested HTML that exceeds the 512 node stack limit
		// This should trigger a panic in the HTML parser, which we recover from
		deeplyNestedHTML := "<div>"
		for i := 0; i < 600; i++ {
			deeplyNestedHTML += "<div><span>"
		}
		deeplyNestedHTML += "Some text content"
		for i := 0; i < 600; i++ {
			deeplyNestedHTML += "</span></div>"
		}
		deeplyNestedHTML += "</div>"

		// Should not panic and should return "other" when htmlToText returns empty string
		result := epc.Classify(deeplyNestedHTML)
		require.Equal(t, "other", result)
	})

	t.Run("test htmlToText with deeply nested HTML", func(t *testing.T) {
		// Generate deeply nested HTML that exceeds the 512 node stack limit
		deeplyNestedHTML := "<div>"
		for i := 0; i < 600; i++ {
			deeplyNestedHTML += "<div><span>"
		}
		deeplyNestedHTML += "Some text content"
		for i := 0; i < 600; i++ {
			deeplyNestedHTML += "</span></div>"
		}
		deeplyNestedHTML += "</div>"

		// Should not panic and should return empty string with error on panic
		result, err := htmlToText(deeplyNestedHTML)
		require.Error(t, err)
		require.Equal(t, "", result)
	})

	t.Run("test htmlToText with normal HTML", func(t *testing.T) {
		normalHTML := `<html><body><h1>Title</h1><p>Some content here</p></body></html>`
		result, err := htmlToText(normalHTML)
		require.NoError(t, err)
		require.NotEmpty(t, result)
	})
}
