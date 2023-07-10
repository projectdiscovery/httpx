package static

import (
	_ "embed"
)

//go:embed html-summary.html
var HtmlTemplate string
