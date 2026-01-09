package pagetypeclassifier

import (
	"strings"
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

	t.Run("test resilience with deeply nested HTML", func(t *testing.T) {
		epc, err := New()
		require.NoError(t, err)
		require.NotNil(t, epc)

		// Generate deeply nested HTML that would have exceeded the 512 node stack limit
		// With our enhanced sanitization and fallback mechanisms, this should now work
		deeplyNestedHTML := "<div>"
		for i := 0; i < 600; i++ {
			deeplyNestedHTML += "<div><span>"
		}
		deeplyNestedHTML += "Some text content"
		for i := 0; i < 600; i++ {
			deeplyNestedHTML += "</span></div>"
		}
		deeplyNestedHTML += "</div>"

		// Should not panic and should successfully classify the content
		result := epc.Classify(deeplyNestedHTML)
		require.NotEmpty(t, result)
		// Should be able to extract and classify the text content
		require.NotEqual(t, "", result)
	})

	t.Run("test htmlToText with deeply nested HTML", func(t *testing.T) {
		// Generate deeply nested HTML that would have exceeded the 512 node stack limit
		deeplyNestedHTML := "<div>"
		for i := 0; i < 600; i++ {
			deeplyNestedHTML += "<div><span>"
		}
		deeplyNestedHTML += "Some text content"
		for i := 0; i < 600; i++ {
			deeplyNestedHTML += "</span></div>"
		}
		deeplyNestedHTML += "</div>"

		// Should not panic and should successfully extract text with enhanced sanitization
		result, err := htmlToText(deeplyNestedHTML)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Contains(t, result, "Some text content")
	})

	t.Run("test htmlToText with normal HTML", func(t *testing.T) {
		normalHTML := `<html><body><h1>Title</h1><p>Some content here</p></body></html>`
		result, err := htmlToText(normalHTML)
		require.NoError(t, err)
		require.NotEmpty(t, result)
	})

	t.Run("test htmlToText with extremely large HTML", func(t *testing.T) {
		// Create a very large HTML document (over 1MB)
		largeContent := strings.Repeat("<p>This is a test paragraph with some content. ", 50000)
		largeHTML := "<html><body>" + largeContent + "</body></html>"
		
		// Should handle large documents without panic
		result, err := htmlToText(largeHTML)
		require.NoError(t, err)
		require.NotEmpty(t, result)
	})

	t.Run("test extractPlainText fallback", func(t *testing.T) {
		htmlWithScriptAndStyle := `<html>
			<head>
				<style>body { color: red; }</style>
				<script>alert('test');</script>
			</head>
			<body>
				<h1>Title</h1>
				<p>Some <strong>important</strong> content here</p>
				<div><span>Nested content</span></div>
			</body>
		</html>`
		
		result := extractPlainText(htmlWithScriptAndStyle)
		require.NotEmpty(t, result)
		require.Contains(t, result, "Title")
		require.Contains(t, result, "important")
		require.Contains(t, result, "content")
		// Should not contain script or style content
		require.NotContains(t, result, "alert")
		require.NotContains(t, result, "color: red")
	})
}
