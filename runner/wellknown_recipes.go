package runner

// WellKnownRecipe documents a composable httpx one-liner for probing well-known resources.
type WellKnownRecipe struct {
	Name  string
	Paths string
	Args  []string
}

// WellKnownRecipes returns README-documented recipes validated by TestWellKnownRecipes.
func WellKnownRecipes() []WellKnownRecipe {
	return []WellKnownRecipe{
		{
			Name:  "security.txt",
			Paths: "/.well-known/security.txt,/security.txt",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains(content_type, "text/plain") && contains(body, "Contact:") && contains_any(body, "mailto:", "https://")`,
			},
		},
		{
			Name:  "robots.txt",
			Paths: "/robots.txt",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains(content_type, "text/plain")`,
			},
		},
		{
			Name:  "sitemap.xml",
			Paths: "/sitemap.xml",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains_any(content_type, "application/xml", "text/xml") && contains(body, "<urlset")`,
			},
		},
		{
			Name:  "humans.txt",
			Paths: "/humans.txt",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains(content_type, "text/plain")`,
			},
		},
		{
			Name:  "ads.txt",
			Paths: "/ads.txt",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains(content_type, "text/plain") && contains(body, "google.com")`,
			},
		},
		{
			Name:  "openid-configuration",
			Paths: "/.well-known/openid-configuration",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains(content_type, "application/json") && contains(body, "\"issuer\"")`,
			},
		},
		{
			Name:  "apple-app-site-association",
			Paths: "/.well-known/apple-app-site-association,/.well-known/apple-app-site-association.json",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains(content_type, "application/json") && contains(body, "\"applinks\"")`,
			},
		},
		{
			Name:  "assetlinks.json",
			Paths: "/.well-known/assetlinks.json",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains(content_type, "application/json") && contains(body, "\"android_app\"")`,
			},
		},
		{
			Name:  "crossdomain.xml",
			Paths: "/crossdomain.xml",
			Args: []string{
				"-mc", "200",
				"-mdc", `contains_any(content_type, "application/xml", "text/xml") && contains(body, "cross-domain-policy")`,
			},
		},
		{
			Name:  "well-known-uri-batch",
			Paths: "/.well-known/security.txt,/.well-known/change-password,/.well-known/openid-configuration",
			Args: []string{
				"-mc", "200",
			},
		},
	}
}

// wellKnownFixtures maps request paths to HTTP responses used by recipe tests.
var wellKnownFixtures = map[string]struct {
	statusCode  int
	contentType string
	body        string
}{
	"/.well-known/security.txt": {
		statusCode:  200,
		contentType: "text/plain; charset=utf-8",
		body:        "Contact: mailto:security@example.com\nPreferred-Languages: en\n",
	},
	"/security.txt": {
		statusCode:  200,
		contentType: "text/plain; charset=utf-8",
		body:        "Contact: https://example.com/security\nPreferred-Languages: en\n",
	},
	"/robots.txt": {
		statusCode:  200,
		contentType: "text/plain",
		body:        "User-agent: *\nDisallow: /admin\n",
	},
	"/sitemap.xml": {
		statusCode:  200,
		contentType: "application/xml",
		body:        `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>`,
	},
	"/humans.txt": {
		statusCode:  200,
		contentType: "text/plain",
		body:        "/* TEAM */\nDeveloper: Example Dev\n",
	},
	"/ads.txt": {
		statusCode:  200,
		contentType: "text/plain",
		body:        "google.com, pub-0000000000000000, DIRECT, f08c47fec0942fa0\n",
	},
	"/.well-known/openid-configuration": {
		statusCode:  200,
		contentType: "application/json",
		body:        `{"issuer":"https://example.com","authorization_endpoint":"https://example.com/auth"}`,
	},
	"/.well-known/apple-app-site-association": {
		statusCode:  200,
		contentType: "application/json",
		body:        `{"applinks":{"apps":[],"details":[]}}`,
	},
	"/.well-known/apple-app-site-association.json": {
		statusCode:  200,
		contentType: "application/json",
		body:        `{"applinks":{"apps":[],"details":[]}}`,
	},
	"/.well-known/assetlinks.json": {
		statusCode:  200,
		contentType: "application/json",
		body:        `[{"relation":["delegate_permission/common.handle_all_urls"],"target":{"namespace":"android_app","package_name":"com.example.app"}}]`,
	},
	"/crossdomain.xml": {
		statusCode:  200,
		contentType: "text/xml",
		body:        `<?xml version="1.0"?><!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd"><cross-domain-policy></cross-domain-policy>`,
	},
	"/.well-known/change-password": {
		statusCode:  200,
		contentType: "text/html",
		body:        "<html><body>Change password</body></html>",
	},
}

// soft404Fixture is an HTML error page that should not match strict well-known recipes.
var soft404Fixture = struct {
	statusCode  int
	contentType string
	body        string
}{
	statusCode:  200,
	contentType: "text/html; charset=utf-8",
	body:        "<html><head><title>Not Found</title></head><body><h1>404</h1></body></html>",
}
