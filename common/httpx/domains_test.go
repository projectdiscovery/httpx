package httpx

import (
	"bytes"
	_ "embed"
	"sort"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

//go:embed test-data/hackerone.html
var rawResponse string

//go:embed test-data/sample_with_js.html
var sampleWithJS string

func TestBodyGrabDoamins(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)
	response := &Response{
		Raw: rawResponse,
	}
	bd := ht.BodyDomainGrab(response)

	sort.Strings(bd.Domains)
	sort.Strings(bd.Fqdns)

	t.Run("body domain grab", func(t *testing.T) {
		require.Equal(t, 24, len(bd.Domains))
		require.Equal(t, 16, len(bd.Fqdns))
	})
}

func TestBodyDomainGrabWithParsers(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	response := &Response{
		Raw:  sampleWithJS,
		Data: []byte(sampleWithJS),
	}
	bd := ht.BodyDomainGrab(response)

	sort.Strings(bd.Domains)
	sort.Strings(bd.Fqdns)

	t.Run("html attributes extract domains", func(t *testing.T) {
		require.Contains(t, bd.Fqdns, "link.example.com")
		require.Contains(t, bd.Fqdns, "sub.link.example.com")
		require.Contains(t, bd.Fqdns, "img.example.org")
		require.Contains(t, bd.Fqdns, "embed.example.net")
		require.Contains(t, bd.Fqdns, "static.example.net")
		require.Contains(t, bd.Fqdns, "www.canonical.example.com")
	})

	t.Run("html meta tags extract domains", func(t *testing.T) {
		require.Contains(t, bd.Fqdns, "meta.example.com")
		require.Contains(t, bd.Fqdns, "cdn.images.example.org")
	})

	t.Run("html form action extracts domain", func(t *testing.T) {
		require.Contains(t, bd.Domains, "formhandler.io")
		require.Contains(t, bd.Fqdns, "api.formhandler.io")
	})

	t.Run("html srcset extracts domains", func(t *testing.T) {
		require.Contains(t, bd.Fqdns, "cdn.video.example.com")
	})

	t.Run("html data-url extracts domain", func(t *testing.T) {
		require.Contains(t, bd.Fqdns, "data-attr.example.com")
	})

	t.Run("html video poster extracts domain", func(t *testing.T) {
		require.Contains(t, bd.Fqdns, "video.example.com")
	})

	t.Run("js string literals extract domains", func(t *testing.T) {
		require.Contains(t, bd.Fqdns, "api.jsconfig.example.com")
		require.Contains(t, bd.Fqdns, "cdn.jsconfig.example.net")
		require.Contains(t, bd.Fqdns, "tracking.analytics.example.org")
		require.Contains(t, bd.Fqdns, "api.fetchcall.example.com")
	})

	t.Run("js array and function literals extract domains", func(t *testing.T) {
		require.Contains(t, bd.Fqdns, "first.arraylit.example.com")
		require.Contains(t, bd.Fqdns, "second.arraylit.example.net")
		require.Contains(t, bd.Fqdns, "widget.funclit.example.org")
	})

	t.Run("all expected domains found", func(t *testing.T) {
		require.GreaterOrEqual(t, len(bd.Fqdns), 19)
		require.GreaterOrEqual(t, len(bd.Domains), 1)
	})

	t.Run("external script src extracts domain", func(t *testing.T) {
		require.Contains(t, bd.Fqdns, "external.cdn.example.com")
	})

	t.Run("relative and special hrefs are skipped", func(t *testing.T) {
		for _, fqdn := range bd.Fqdns {
			require.NotContains(t, fqdn, "relative")
			require.NotContains(t, fqdn, "javascript")
		}
	})
}

func TestBodyDomainGrabEmptyBody(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	response := &Response{Raw: "", Data: nil}
	bd := ht.BodyDomainGrab(response)

	require.Empty(t, bd.Domains)
	require.Empty(t, bd.Fqdns)
}

func TestBodyDomainGrabNonHTML(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	plaintext := `Visit 'api.plain.example.com' for more info`
	response := &Response{
		Raw:  plaintext,
		Data: []byte(plaintext),
	}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "api.plain.example.com")
}

func TestBodyDomainGrabJavaScriptBody(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	script := "const api = `https://js-only.example.com/v1`;"
	response := &Response{
		Raw:  script,
		Data: []byte(script),
		Headers: map[string][]string{
			"Content-Type": {"application/javascript"},
		},
	}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "js-only.example.com")
}

func TestLooksLikeHTML_UTF8BOM(t *testing.T) {
	require.True(t, looksLikeHTML([]byte("\xef\xbb\xbf<!DOCTYPE html><html></html>")))
}

func TestBodyDomainGrabBrokenJS(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body><script>var x = {{{invalid js; "https://shouldskip.example.com"</script></body></html>`
	response := &Response{
		Raw:  html,
		Data: []byte(html),
	}
	bd := ht.BodyDomainGrab(response)
	require.NotNil(t, bd)
}

func TestExtractDomainsFromJS(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	script := `
		var url = "https://api.test.example.com/v1/users";
		var cdn = "https://cdn.test.example.net/assets/main.js";
		var num = 42;
		var noDomain = "just a plain string";
	`
	extractDomainsFromJS(script, domains, fqdns, "")

	require.Contains(t, fqdns, "api.test.example.com")
	require.Contains(t, fqdns, "cdn.test.example.net")
	require.Equal(t, 2, len(fqdns))
}

func TestExtractDomainsFromHTML(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	html := []byte(`<html>
		<body>
			<a href="https://link.test.example.com/page">link</a>
			<img src="https://img.test.example.org/pic.png" />
			<script>var x = "https://inline.test.example.net/api";</script>
		</body>
	</html>`)

	inlineScripts := extractDomainsFromHTML(html, domains, fqdns, "")

	require.Contains(t, fqdns, "link.test.example.com")
	require.Contains(t, fqdns, "img.test.example.org")
	require.Len(t, inlineScripts, 1)
	require.Contains(t, inlineScripts[0], "inline.test.example.net")
}

// --- False positive rejection tests ---

func TestFalsePositive_IPAddresses(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://192.168.1.1/admin">router</a>
		<a href="https://10.0.0.1:8080/api">internal</a>
		<script>var ip = "https://172.16.0.1/test";</script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	for _, d := range bd.Domains {
		require.False(t, isAllNumericParts(d), "IP address should not appear in domains: %s", d)
	}
	for _, f := range bd.Fqdns {
		require.False(t, isAllNumericParts(f), "IP address should not appear in fqdns: %s", f)
	}
}

func TestFalsePositive_PackageNames(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<script>
			var pkg = "com.google.android.apps";
			var java = "org.apache.commons.lang3";
			var io = "io.netty.handler.codec";
		</script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	for _, f := range bd.Fqdns {
		require.NotContains(t, f, "com.google.android", "Java/Android package name should be rejected: %s", f)
		require.NotContains(t, f, "org.apache.commons", "Java package name should be rejected: %s", f)
		require.NotContains(t, f, "io.netty.handler", "Java package name should be rejected: %s", f)
	}
}

func TestFalsePositive_FileExtensions(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="/downloads/report.pdf">report</a>
		<a href="/assets/style.css">css</a>
		<a href="/bundle/app.js">js</a>
		<img src="/images/logo.png" />
		<script>var file = "/path/to/config.yml";</script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	for _, f := range bd.Fqdns {
		require.NotEqual(t, "report.pdf", f)
		require.NotEqual(t, "style.css", f)
		require.NotEqual(t, "app.js", f)
		require.NotEqual(t, "logo.png", f)
	}
}

func TestFalsePositive_VersionStrings(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<script>
			var version = "v1.2.3";
			var semver = "16.3.1";
			var nodeVer = "node18.2";
		</script>
		<p>Running version 2.4.1 of the software</p>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Empty(t, bd.Fqdns, "version strings should not produce fqdns")
	require.Empty(t, bd.Domains, "version strings should not produce domains")
}

func TestFalsePositive_CSSClassNames(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<div class="header.main container.fluid">test</div>
		<style>.nav.active { color: red; }</style>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	for _, f := range bd.Fqdns {
		require.NotContains(t, f, "header.main")
		require.NotContains(t, f, "container.fluid")
		require.NotContains(t, f, "nav.active")
	}
}

func TestFalsePositive_MinifiedJSVars(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	// minified JS often has expressions like e.target, n.value, t.id
	html := `<html><body><script>var a=e.target,b=n.value,c=t.id;</script></body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Empty(t, bd.Fqdns, "minified JS property accesses should not produce fqdns")
	require.Empty(t, bd.Domains, "minified JS property accesses should not produce domains")
}

func TestFalsePositive_MailtoAndTelLinks(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="mailto:user@test.example.com">email</a>
		<a href="tel:+1234567890">call</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	// mailto and tel links should not be parsed by the HTML extractor
	// but the regex fallback may still catch domains from the raw text
	require.NotNil(t, bd)
}

func TestFalsePositive_DataURIs(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<img src="data:image/png;base64,iVBORw0KGgo=" />
		<a href="data:text/html,<h1>Hello</h1>">data link</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Empty(t, bd.Fqdns, "data URIs should not produce fqdns")
	require.Empty(t, bd.Domains, "data URIs should not produce domains")
}

func TestFalsePositive_WebpackChunks(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<script src="/static/js/vendors~main.chunk.js"></script>
		<script src="/static/js/runtime~main.js"></script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	for _, f := range bd.Fqdns {
		require.NotContains(t, f, "chunk")
		require.NotContains(t, f, "runtime")
	}
}

// --- Edge case tests ---

func TestEdgeCase_ProtocolRelativeURLs(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<script src="//cdn.proto-relative.example.com/lib.js"></script>
		<img src="//images.proto-relative.example.net/pic.png" />
		<link href="//fonts.proto-relative.example.org/font.woff2" />
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "cdn.proto-relative.example.com")
	require.Contains(t, bd.Fqdns, "images.proto-relative.example.net")
	require.Contains(t, bd.Fqdns, "fonts.proto-relative.example.org")
}

func TestEdgeCase_MetaRefreshRedirect(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><head>
		<meta http-equiv="refresh" content="0;url=https://redirect.meta-refresh.example.com/target" />
	</head><body></body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "redirect.meta-refresh.example.com")
}

func TestEdgeCase_JSONLDScripts(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<script type="application/ld+json">
		{
			"@context": "https://schema.org",
			"@type": "Organization",
			"url": "https://www.jsonld-org.example.com",
			"logo": "https://cdn.jsonld-org.example.com/logo.png"
		}
		</script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "www.jsonld-org.example.com")
	require.Contains(t, bd.Fqdns, "cdn.jsonld-org.example.com")
}

func TestEdgeCase_TrailingDots(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://trailing-dot.example.com./path">link</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "trailing-dot.example.com")
	for _, f := range bd.Fqdns {
		require.False(t, strings.HasSuffix(f, "."), "domain should not have trailing dot: %s", f)
	}
}

func TestEdgeCase_Deduplication(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://dedup.example.com/page1">link1</a>
		<a href="https://dedup.example.com/page2">link2</a>
		<a href="https://dedup.example.com/page3">link3</a>
		<script>
			var x = "https://dedup.example.com/api";
			var y = "https://dedup.example.com/other";
		</script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	count := 0
	for _, f := range bd.Fqdns {
		if f == "dedup.example.com" {
			count++
		}
	}
	require.Equal(t, 1, count, "duplicate fqdns should be deduplicated")
}

func TestEdgeCase_InputDomainExclusion(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://self.example.com/page">self</a>
		<a href="https://other.different.net/page">other</a>
	</body></html>`
	response := &Response{
		Raw:   html,
		Data:  []byte(html),
		Input: "example.com",
	}
	bd := ht.BodyDomainGrab(response)

	// example.com is the input domain, should be excluded from domains list
	for _, d := range bd.Domains {
		require.NotEqual(t, "example.com", d, "input domain should be excluded from domains")
	}
	// self.example.com equals the input, should be excluded from fqdns
	for _, f := range bd.Fqdns {
		require.NotEqual(t, "example.com", f, "input should be excluded from fqdns")
	}
	require.Contains(t, bd.Domains, "different.net")
	require.Contains(t, bd.Fqdns, "other.different.net")
}

func TestEdgeCase_InputDomainExclusionWithPort(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://self.example.com/page">self</a>
		<a href="https://other.different.net/page">other</a>
	</body></html>`
	response := &Response{
		Raw:   html,
		Data:  []byte(html),
		Input: "example.com:8080",
	}
	bd := ht.BodyDomainGrab(response)

	for _, d := range bd.Domains {
		require.NotEqual(t, "example.com", d, "input host should be excluded from domains")
	}
	for _, f := range bd.Fqdns {
		require.NotEqual(t, "example.com", f, "input host should be excluded from fqdns")
	}
	require.Contains(t, bd.Domains, "different.net")
	require.Contains(t, bd.Fqdns, "other.different.net")
}

func TestEdgeCase_EmptyAndWhitespaceScripts(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<script>   </script>
		<script></script>
		<script>
		</script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.NotNil(t, bd)
	require.Empty(t, bd.Fqdns)
}

func TestEdgeCase_MultipleScriptsSomeBroken(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<script>var x = {{{ broken }</script>
		<script>var url = "https://valid.multi-script.example.com/api";</script>
		<script>function() { syntax error</script>
		<script>fetch("https://also-valid.multi-script.example.net/data");</script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "valid.multi-script.example.com")
	require.Contains(t, bd.Fqdns, "also-valid.multi-script.example.net")
}

func TestEdgeCase_URLsWithQueryAndFragment(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://query.example.com/path?foo=bar&baz=1">query</a>
		<a href="https://fragment.example.com/path#section">fragment</a>
		<a href="https://both.example.com/path?x=1#top">both</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "query.example.com")
	require.Contains(t, bd.Fqdns, "fragment.example.com")
	require.Contains(t, bd.Fqdns, "both.example.com")
}

func TestEdgeCase_MixedCaseURLs(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="HTTPS://UPPER.CASE.EXAMPLE.COM/PATH">upper</a>
		<a href="Https://Mixed.Case.Example.Net/Path">mixed</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "upper.case.example.com")
	require.Contains(t, bd.Fqdns, "mixed.case.example.net")
}

func TestEdgeCase_URLsWithPorts(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://ported.example.com:8443/api">port</a>
		<script>var url = "https://ported-js.example.net:3000/ws";</script>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "ported.example.com")
	require.Contains(t, bd.Fqdns, "ported-js.example.net")
	for _, f := range bd.Fqdns {
		require.NotContains(t, f, ":", "port numbers should not appear in extracted domains")
	}
}

func TestEdgeCase_URLsWithAuth(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://user:pass@authed.example.com/page">authed</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "authed.example.com")
}

func TestEdgeCase_JSArrowFunctions(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	script := `
		const fetchData = () => fetch("https://api.arrow.example.com/data");
		const urls = ["a", "b"].map(x => "https://map." + x + ".example.net");
		const handler = async () => {
			const res = await fetch("https://async-arrow.example.org/endpoint");
			return res;
		};
	`
	extractDomainsFromJS(script, domains, fqdns, "")

	require.Contains(t, fqdns, "api.arrow.example.com")
	require.Contains(t, fqdns, "async-arrow.example.org")
}

func TestEdgeCase_JSObjectNesting(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	script := `
		var config = {
			api: {
				base: "https://nested-api.example.com/v1",
				endpoints: {
					users: "https://nested-users.example.com/users",
					deep: {
						level: "https://nested-deep.example.net/deep"
					}
				}
			}
		};
	`
	extractDomainsFromJS(script, domains, fqdns, "")

	require.Contains(t, fqdns, "nested-api.example.com")
	require.Contains(t, fqdns, "nested-users.example.com")
	require.Contains(t, fqdns, "nested-deep.example.net")
}

func TestEdgeCase_JSTryCatchFinally(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	script := `
		try {
			fetch("https://try-block.example.com/api");
		} catch(e) {
			fetch("https://catch-block.example.net/error");
		} finally {
			fetch("https://finally-block.example.org/cleanup");
		}
	`
	extractDomainsFromJS(script, domains, fqdns, "")

	require.Contains(t, fqdns, "try-block.example.com")
	require.Contains(t, fqdns, "catch-block.example.net")
	require.Contains(t, fqdns, "finally-block.example.org")
}

func TestEdgeCase_JSConditionalTernary(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	script := `
		var url = isProd
			? "https://prod.ternary.example.com/api"
			: "https://dev.ternary.example.net/api";
	`
	extractDomainsFromJS(script, domains, fqdns, "")

	require.Contains(t, fqdns, "prod.ternary.example.com")
	require.Contains(t, fqdns, "dev.ternary.example.net")
}

func TestEdgeCase_JSSwitchCase(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	script := `
		switch(env) {
			case "prod":
				url = "https://prod.switch.example.com/api";
				break;
			case "staging":
				url = "https://staging.switch.example.net/api";
				break;
			default:
				url = "https://default.switch.example.org/api";
		}
	`
	extractDomainsFromJS(script, domains, fqdns, "")

	require.Contains(t, fqdns, "prod.switch.example.com")
	require.Contains(t, fqdns, "staging.switch.example.net")
	require.Contains(t, fqdns, "default.switch.example.org")
}

func TestEdgeCase_JSLoops(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	script := `
		for (var i = 0; i < 10; i++) {
			fetch("https://for-loop.example.com/item");
		}
		while (true) {
			fetch("https://while-loop.example.net/poll");
			break;
		}
		do {
			fetch("https://do-while.example.org/retry");
		} while (false);
	`
	extractDomainsFromJS(script, domains, fqdns, "")

	require.Contains(t, fqdns, "for-loop.example.com")
	require.Contains(t, fqdns, "while-loop.example.net")
	require.Contains(t, fqdns, "do-while.example.org")
}

func TestEdgeCase_JSIfElse(t *testing.T) {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	script := `
		if (condition) {
			url = "https://if-branch.example.com/a";
		} else if (other) {
			url = "https://elseif-branch.example.net/b";
		} else {
			url = "https://else-branch.example.org/c";
		}
	`
	extractDomainsFromJS(script, domains, fqdns, "")

	require.Contains(t, fqdns, "if-branch.example.com")
	require.Contains(t, fqdns, "elseif-branch.example.net")
	require.Contains(t, fqdns, "else-branch.example.org")
}

func TestEdgeCase_HTMLEntitiesInURLs(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	// goquery auto-decodes &amp; to &
	html := `<html><body>
		<a href="https://entity.example.com/path?a=1&amp;b=2">entity</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "entity.example.com")
}

func TestEdgeCase_FormactionAttribute(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<form>
			<button formaction="https://formaction-btn.example.com/submit">Submit</button>
		</form>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "formaction-btn.example.com")
}

func TestEdgeCase_CiteAttribute(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<blockquote cite="https://cite-source.example.com/article">quoted text</blockquote>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "cite-source.example.com")
}

func TestEdgeCase_OpenGraphAndTwitterMeta(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><head>
		<meta property="og:url" content="https://og-url.example.com/page" />
		<meta property="og:image" content="https://og-image.example.net/img.jpg" />
		<meta name="twitter:image" content="https://twitter-img.example.org/card.png" />
	</head><body></body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "og-url.example.com")
	require.Contains(t, bd.Fqdns, "og-image.example.net")
	require.Contains(t, bd.Fqdns, "twitter-img.example.org")
}

func TestEdgeCase_SrcsetMultipleEntries(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<img srcset="https://srcset1.example.com/small.jpg 480w, https://srcset2.example.net/medium.jpg 800w, https://srcset3.example.org/large.jpg 1200w" />
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "srcset1.example.com")
	require.Contains(t, bd.Fqdns, "srcset2.example.net")
	require.Contains(t, bd.Fqdns, "srcset3.example.org")
}

func TestEdgeCase_DataAttributes(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<div data-url="https://data-url-attr.example.com/api"></div>
		<div data-href="https://data-href-attr.example.net/link"></div>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "data-url-attr.example.com")
	require.Contains(t, bd.Fqdns, "data-href-attr.example.net")
}

func TestEdgeCase_LargeBodyNoPanic(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	// generate a large body with repeated content
	var builder strings.Builder
	builder.WriteString("<html><body>")
	for i := 0; i < 1000; i++ {
		builder.WriteString(`<a href="https://bulk.example.com/page">link</a>`)
	}
	builder.WriteString("</body></html>")
	body := builder.String()

	response := &Response{Raw: body, Data: []byte(body)}
	bd := ht.BodyDomainGrab(response)

	require.NotNil(t, bd)
	require.Contains(t, bd.Fqdns, "bulk.example.com")
}

func TestEdgeCase_OnlyRawNoData(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	// r.Data is nil but r.Raw has content — HTML parser skipped, regex catches it
	raw := `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href="https://raw-only.example.com/page">test</a>`
	response := &Response{Raw: raw, Data: nil}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "raw-only.example.com")
}

func TestEdgeCase_SubdomainVsDomain(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://example.com/root">root domain</a>
		<a href="https://sub.example.com/sub">subdomain</a>
		<a href="https://deep.sub.example.com/deep">deep sub</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Domains, "example.com")
	require.Contains(t, bd.Fqdns, "sub.example.com")
	require.Contains(t, bd.Fqdns, "deep.sub.example.com")
	// root domain (example.com) should be in domains but NOT in fqdns
	// (because d == val for a root domain, so the fqdn branch is skipped)
	for _, f := range bd.Fqdns {
		require.NotEqual(t, "example.com", f, "root domain should not appear in fqdns list")
	}
}

func TestEdgeCase_InternationalTLDs(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	html := `<html><body>
		<a href="https://test.example.co.uk/page">uk</a>
		<a href="https://test.example.com.au/page">au</a>
	</body></html>`
	response := &Response{Raw: html, Data: []byte(html)}
	bd := ht.BodyDomainGrab(response)

	require.Contains(t, bd.Fqdns, "test.example.co.uk")
	require.Contains(t, bd.Fqdns, "test.example.com.au")
}

// helper for IP check test
func isAllNumericParts(d string) bool {
	for _, part := range strings.Split(d, ".") {
		allDigits := true
		for _, c := range part {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if !allDigits {
			return false
		}
	}
	return true
}

// --- Unit tests for hostnameFromURL ---

func TestHostnameFromURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"https url", "https://example.com/path", "example.com"},
		{"http url", "http://sub.example.com/path", "sub.example.com"},
		{"protocol-relative", "//cdn.example.com/file.js", "cdn.example.com"},
		{"with port", "https://example.com:8443/api", "example.com"},
		{"with auth", "https://user:pass@example.com/page", "example.com"},
		{"with query", "https://example.com/path?q=1", "example.com"},
		{"with fragment", "https://example.com/path#section", "example.com"},
		{"empty string", "", ""},
		{"hash only", "#section", ""},
		{"javascript scheme", "javascript:void(0)", ""},
		{"data uri", "data:text/html,<h1>hi</h1>", ""},
		{"mailto", "mailto:user@example.com", ""},
		{"tel", "tel:+1234567890", ""},
		{"blob", "blob:https://example.com/uuid", ""},
		{"about", "about:blank", ""},
		{"relative path", "/path/to/page", ""},
		{"bare domain no scheme", "example.com", ""},
		{"no dots", "https://localhost/path", ""},
		{"ip address", "https://192.168.1.1/admin", "192.168.1.1"},
		{"uppercase scheme", "HTTPS://EXAMPLE.COM/PATH", "EXAMPLE.COM"},
		{"whitespace", "  https://trimmed.example.com/path  ", "trimmed.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hostnameFromURL(tc.input)
			require.Equal(t, tc.expected, result)
		})
	}
}

// --- Unit tests for addDomainCandidate ---

func TestAddDomainCandidate(t *testing.T) {
	t.Run("valid fqdn", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("sub.example.com", domains, fqdns, "")
		require.Contains(t, fqdns, "sub.example.com")
		require.Contains(t, domains, "example.com")
	})

	t.Run("root domain only goes to domains not fqdns", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("example.com", domains, fqdns, "")
		require.Contains(t, domains, "example.com")
		require.Empty(t, fqdns)
	})

	t.Run("trailing dot is stripped", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("sub.example.com.", domains, fqdns, "")
		require.Contains(t, fqdns, "sub.example.com")
	})

	t.Run("uppercase is lowered", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("SUB.EXAMPLE.COM", domains, fqdns, "")
		require.Contains(t, fqdns, "sub.example.com")
	})

	t.Run("input domain excluded from domains", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("sub.example.com", domains, fqdns, "example.com")
		require.Empty(t, domains)
		require.Contains(t, fqdns, "sub.example.com")
	})

	t.Run("input fqdn excluded from fqdns", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("sub.example.com", domains, fqdns, "sub.example.com")
		require.Empty(t, fqdns)
	})

	t.Run("input host with port excluded from domains", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("sub.example.com", domains, fqdns, "example.com:443")
		require.Empty(t, domains)
		require.Contains(t, fqdns, "sub.example.com")
	})

	t.Run("empty string rejected", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("", domains, fqdns, "")
		require.Empty(t, domains)
		require.Empty(t, fqdns)
	})

	t.Run("whitespace only rejected", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("   ", domains, fqdns, "")
		require.Empty(t, domains)
		require.Empty(t, fqdns)
	})

	t.Run("ip address rejected", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("192.168.1.1", domains, fqdns, "")
		require.Empty(t, domains)
		require.Empty(t, fqdns)
	})

	t.Run("single label rejected", func(t *testing.T) {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		addDomainCandidate("localhost", domains, fqdns, "")
		require.Empty(t, domains)
		require.Empty(t, fqdns)
	})
}

// --- Benchmarks ---

func BenchmarkBodyDomainGrab_HackerOne(b *testing.B) {
	ht, err := New(&DefaultOptions)
	if err != nil {
		b.Fatal(err)
	}
	response := &Response{
		Raw:  rawResponse,
		Data: []byte(rawResponse),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ht.BodyDomainGrab(response)
	}
}

func BenchmarkBodyDomainGrab_SmallPage(b *testing.B) {
	ht, err := New(&DefaultOptions)
	if err != nil {
		b.Fatal(err)
	}
	response := &Response{
		Raw:  sampleWithJS,
		Data: []byte(sampleWithJS),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ht.BodyDomainGrab(response)
	}
}

func BenchmarkBodyDomainGrab_RegexOnly(b *testing.B) {
	response := &Response{
		Raw:  rawResponse,
		Data: []byte(rawResponse),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		extractDomainsFromRegex(response.Raw, domains, fqdns, "")
	}
}

func BenchmarkBodyDomainGrab_HTMLOnly(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domains := make(map[string]struct{})
		fqdns := make(map[string]struct{})
		extractDomainsFromHTML([]byte(rawResponse), domains, fqdns, "")
	}
}

func BenchmarkBodyDomainGrab_JSOnly(b *testing.B) {
	scripts := []string{}
	extractDomainsFromHTML([]byte(rawResponse), make(map[string]struct{}), make(map[string]struct{}), "")
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte(rawResponse)))
	doc.Find("script").Each(func(_ int, s *goquery.Selection) {
		if _, ok := s.Attr("src"); !ok {
			if text := s.Text(); strings.TrimSpace(text) != "" {
				scripts = append(scripts, text)
			}
		}
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, script := range scripts {
			domains := make(map[string]struct{})
			fqdns := make(map[string]struct{})
			extractDomainsFromJS(script, domains, fqdns, "")
		}
	}
}

func BenchmarkBodyDomainGrab_JSON(b *testing.B) {
	ht, err := New(&DefaultOptions)
	if err != nil {
		b.Fatal(err)
	}
	json := `{"url":"https://api.example.com/v1","cdn":"https://cdn.example.net/assets","callback":"https://hooks.example.org/notify"}`
	response := &Response{
		Raw:  json,
		Data: []byte(json),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ht.BodyDomainGrab(response)
	}
}

func BenchmarkBodyDomainGrab_PlainText(b *testing.B) {
	ht, err := New(&DefaultOptions)
	if err != nil {
		b.Fatal(err)
	}
	text := `'api.example.com' and 'cdn.example.net' are the endpoints`
	response := &Response{
		Raw:  text,
		Data: []byte(text),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ht.BodyDomainGrab(response)
	}
}
