package errorpageclassifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorPageClassifier(t *testing.T) {
	t.Run("test creation of new ErrorPageClassifier", func(t *testing.T) {
		epc := New()
		assert.NotNil(t, epc)
	})

	t.Run("test classification non error page text", func(t *testing.T) {
		epc := New()
		assert.Equal(t, "nonerror", epc.Classify(`<!DOCTYPE html>
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
		epc := New()
		assert.Equal(t, "error", epc.Classify(`<!DOCTYPE html>
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
}
