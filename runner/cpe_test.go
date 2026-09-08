package runner

import (
	"testing"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func TestSanitizeCPEVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain semver", "2.4.7", "2.4.7"},
		{"case preserved", "1.0.0-RC1", "1.0.0-RC1"},
		{"spaces to underscore", "10 0", "10_0"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeCPEVersion(tt.in); got != tt.want {
				t.Fatalf("sanitizeCPEVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTechDetectRequired(t *testing.T) {
	tests := []struct {
		name    string
		options *Options
		want    bool
	}{
		{"nothing enabled", &Options{}, false},
		{"tech-detect flag", &Options{TechDetect: true}, true},
		{"json output", &Options{JSONOutput: true}, true},
		{"csv output", &Options{CSVOutput: true}, true},
		{"asset upload", &Options{AssetUpload: true}, true},
		// issue #2476: -cpe alone must turn tech-detect on, because CPE
		// enrichment reuses the versions wappalyzer extracts.
		{"cpe alone enables tech-detect", &Options{CPEDetect: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := techDetectRequired(tt.options); got != tt.want {
				t.Fatalf("techDetectRequired(%+v) = %v, want %v", tt.options, got, tt.want)
			}
		})
	}
}

func TestSetCPEVersion(t *testing.T) {
	tests := []struct {
		name    string
		cpe     string
		version string
		want    string
	}{
		{
			name:    "fills version slot",
			cpe:     "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
			version: "14.2.3",
			want:    "cpe:2.3:a:vercel:next.js:14.2.3:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version leaves cpe unchanged",
			cpe:     "cpe:2.3:a:apache:apache_http_server:*:*:*:*:*:*:*:*",
			version: "",
			want:    "cpe:2.3:a:apache:apache_http_server:*:*:*:*:*:*:*:*",
		},
		{
			name:    "empty cpe stays empty",
			cpe:     "",
			version: "1.2.3",
			want:    "",
		},
		{
			name:    "malformed cpe returned unchanged",
			cpe:     "not-a-cpe",
			version: "1.2.3",
			want:    "not-a-cpe",
		},
		{
			name:    "truncated cpe returned unchanged",
			cpe:     "cpe:2.3:a:vendor:product:*",
			version: "1.2.3",
			want:    "cpe:2.3:a:vendor:product:*",
		},
		{
			name:    "version with colon leaves cpe unchanged",
			cpe:     "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			version: "1.0:beta",
			want:    "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with wildcard leaves cpe unchanged",
			cpe:     "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			version: "2.*",
			want:    "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := setCPEVersion(tt.cpe, tt.version); got != tt.want {
				t.Fatalf("setCPEVersion(%q, %q) = %q, want %q", tt.cpe, tt.version, got, tt.want)
			}
		})
	}
}

func TestNormalizeProductName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"WebLogic Server", "weblogicserver"},          // wappalyzer display form
		{"weblogic_server", "weblogicserver"},          // awesome-search-queries snake_case
		{"Next.js", "nextjs"},                          // punctuation dropped
		{"veeder-root", "veederroot"},                  // hyphen dropped
		{"  Apache HTTP Server  ", "apachehttpserver"}, // surrounding space
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeProductName(tt.in); got != tt.want {
			t.Fatalf("normalizeProductName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBuildTechVersionMap(t *testing.T) {
	techs := []string{
		"Apache HTTP Server:2.4.7",
		"PHP:5.5.9",
		"Bootstrap", // no version -> not in map
		"Next.js:14.2.3",
		"jQuery:", // empty version -> not in map
	}
	got := buildTechVersionMap(techs)

	want := map[string]string{
		"apachehttpserver": "2.4.7",
		"php":              "5.5.9",
		"nextjs":           "14.2.3",
	}
	if len(got) != len(want) {
		t.Fatalf("map size = %d, want %d (%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["bootstrap"]; ok {
		t.Fatalf("bootstrap should not be present (no version)")
	}
	if _, ok := got["jquery"]; ok {
		t.Fatalf("jquery should not be present (empty version)")
	}
}

func TestProductLookupKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "liferay portal strips suffix",
			in:   "liferay_portal",
			want: []string{"liferayportal", "liferay"},
		},
		{
			name: "confluence server strips suffix",
			in:   "confluence_server",
			want: []string{"confluenceserver", "confluence"},
		},
		{
			name: "tableau server strips suffix",
			in:   "tableau_server",
			want: []string{"tableauserver", "tableau"},
		},
		{
			name: "longest suffix takes priority",
			in:   "ansible_policy_manager",
			want: []string{"ansiblepolicymanager", "ansible", "ansiblepolicy"},
		},
		{
			name: "compound name uses primary product",
			in:   "digital_experience_platform,liferay_portal",
			want: []string{"digitalexperienceplatform", "digitalexperience", "digital"},
		},
		{
			name: "display name unchanged",
			in:   "Apache HTTP Server",
			want: []string{"apachehttpserver"},
		},
		{
			name: "simple product",
			in:   "next.js",
			want: []string{"nextjs"},
		},
		{
			name: "known short alias",
			in:   "d3.js",
			want: []string{"d3js", "d3"},
		},
		{
			name: "known display alias",
			in:   "matomo",
			want: []string{"matomo", "matomoanalytics"},
		},
		{
			name: "empty",
			in:   "",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := productLookupKeys(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("productLookupKeys(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("productLookupKeys(%q)[%d] = %q, want %q (full: %v)", tt.in, i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestFallbackProductLookupKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "bare product", in: "tomcat", want: []string{"tomcat"}},
		{name: "known suffix", in: "confluence_server", want: []string{"confluenceserver", "confluence"}},
		{name: "known short alias", in: "d3.js", want: []string{"d3js", "d3"}},
		{name: "known display alias", in: "matomo", want: []string{"matomo", "matomoanalytics"}},
		{name: "does not use arbitrary prefix", in: "tomcat_jk_connector", want: []string{"tomcatjkconnector"}},
		{name: "compound uses primary", in: "digital_experience_platform,liferay_portal", want: []string{"digitalexperienceplatform", "digitalexperience"}},
		{name: "empty", in: "", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fallbackProductLookupKeys(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("fallbackProductLookupKeys(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("fallbackProductLookupKeys(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLookupTechVersion(t *testing.T) {
	t.Parallel()

	technologies := []string{
		"Liferay:7.3.5",
		"Confluence:8.5.1",
		"Tableau:2023.1",
		"Apache HTTP Server:2.4.7",
		"Ansible:2.14.0",
		"Apache Tomcat:9.0.65",
		"Preact:10.5.0",
		"D3:7.8.5",
		"Atlassian Jira:9.12.0",
		"Matomo Analytics:5.0.0",
	}
	versions := buildTechVersionMap(technologies)
	candidates := buildTechnologyVersions(technologies)

	tests := []struct {
		product   string
		want      string
		wantFound bool
	}{
		{"liferay_portal", "7.3.5", true},
		{"liferay", "7.3.5", true},
		{"confluence_server", "8.5.1", true},
		{"tableau_server", "2023.1", true},
		{"ansible_policy_manager", "2.14.0", true},
		{"Apache HTTP Server", "2.4.7", true},
		{"phpcollab", "", false},
		{"unknown_product", "", false},
		// #2550: vendor-prefixed wappalyzer name ("Apache Tomcat") vs. the
		// bare CPE product name ("tomcat") - resolved by the whole-word
		// token fallback.
		{"tomcat", "9.0.65", true},
		{"d3.js", "7.8.5", true},
		{"jira", "9.12.0", true},
		{"matomo", "5.0.0", true},
		// CodeRabbit review on #2569: "react" is a character-for-character
		// substring of "preact", but they must never be treated as a match.
		// Whole-word tokenization keeps them distinct ("react" != "preact"
		// as tokens), unlike a raw substring check.
		{"react", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.product, func(t *testing.T) {
			vendor := map[string]string{
				"tomcat": "apache",
				"jira":   "atlassian",
			}[tt.product]
			got, ok := lookupTechVersion(tt.product, vendor, versions, candidates)
			if ok != tt.wantFound {
				t.Fatalf("lookupTechVersion(%q) found = %v, want %v", tt.product, ok, tt.wantFound)
			}
			if got != tt.want {
				t.Fatalf("lookupTechVersion(%q) = %q, want %q", tt.product, got, tt.want)
			}
		})
	}
}

func TestTechnologyTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "vendor prefix", in: "Apache Tomcat", want: []string{"apache", "tomcat"}},
		{name: "punctuation", in: "D3.js / Plugin", want: []string{"d3", "js", "plugin"}},
		{name: "underscore", in: "dashboard_console", want: []string{"dashboard", "console"}},
		{name: "case folding", in: "PreACT", want: []string{"preact"}},
		{name: "empty", in: "", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := technologyTokens(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("technologyTokens(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("technologyTokens(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestStrongTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "keeps specific words", in: "Apache Tomcat Server", want: []string{"apache", "tomcat"}},
		{name: "drops generic words", in: "Cloud Web Application Framework", want: nil},
		{name: "drops short words", in: "D3.js API", want: nil},
		{name: "keeps token boundaries", in: "React Preact", want: []string{"react", "preact"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strongTokens(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("strongTokens(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("strongTokens(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestBuildTechnologyVersions(t *testing.T) {
	t.Parallel()

	candidates := buildTechnologyVersions([]string{
		"Apache Tomcat:9.0.65",
		"Oracle Tomcat:10.1.0",
		"Vendor Dashboard:1.0",
		"D3:7.8.5",
		"Missing Version",
		"Blank:",
		"---:1.0",
	})
	if len(candidates) != 4 {
		t.Fatalf("candidates = %#v, want 4 versioned candidates", candidates)
	}
	if candidates[0].version != "9.0.65" {
		t.Fatalf("first candidate version = %q, want 9.0.65", candidates[0].version)
	}
	for _, token := range []string{"apache", "tomcat"} {
		if !sliceContains(candidates[0].tokens, token) {
			t.Fatalf("first candidate tokens = %v, want %q", candidates[0].tokens, token)
		}
	}
}

func TestLookupTechVersionRejectsAmbiguousFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		product      string
		vendor       string
		technologies []string
		want         string
		wantFound    bool
	}{
		{
			name:         "same fallback name has different versions",
			product:      "dashboard",
			vendor:       "acmecorp",
			technologies: []string{"AcmeCorp Dashboard:1.0", "AcmeCorp Dashboard:2.0"},
		},
		{
			name:         "conflict is independent of input order",
			product:      "dashboard",
			vendor:       "acmecorp",
			technologies: []string{"AcmeCorp Dashboard:2.0", "AcmeCorp Dashboard:1.0"},
		},
		{
			name:         "vendor disambiguates shared product token",
			product:      "tomcat",
			vendor:       "apache",
			technologies: []string{"Apache Tomcat:9.0.65", "Oracle Tomcat:10.1.0"},
			want:         "9.0.65",
			wantFound:    true,
		},
		{
			name:         "matching fallback candidates agree",
			product:      "dashboard",
			vendor:       "acmecorp",
			technologies: []string{"AcmeCorp Dashboard:1.0", "AcmeCorp Dashboard:1.0"},
			want:         "1.0",
			wantFound:    true,
		},
		{
			name:         "secondary compound product is ignored",
			product:      "digital_experience_platform,liferay_portal",
			vendor:       "acmecorp",
			technologies: []string{"AcmeCorp Liferay:7.3.5"},
		},
		{
			name:         "exact match wins before ambiguous fallback",
			product:      "dashboard_console",
			vendor:       "acmecorp",
			technologies: []string{"Dashboard Console:9.0", "AcmeCorp Dashboard:1.0", "AcmeCorp Dashboard:2.0"},
			want:         "9.0",
			wantFound:    true,
		},
		{
			name:         "shared brand is not product evidence",
			product:      "google_maps",
			vendor:       "google",
			technologies: []string{"Google Analytics:4.0"},
		},
		{
			name:         "unrelated vendor rejects broad product token",
			product:      "wp-google-maps",
			vendor:       "wpgmaps",
			technologies: []string{"Google Analytics:4.0"},
		},
		{
			name:         "extended vendor product is not shortened",
			product:      "experience_manager",
			vendor:       "adobe",
			technologies: []string{"Adobe Experience Manager Edge Delivery Services:1.0"},
		},
		{
			name:         "connector is not parent product",
			product:      "tomcat_jk_connector",
			vendor:       "apache",
			technologies: []string{"Apache Tomcat:9.0.65"},
		},
		{
			name:         "code editor is not visual studio",
			product:      "visual_studio_code",
			vendor:       "microsoft",
			technologies: []string{"Microsoft Visual Studio:17.0"},
		},
		{
			name:         "service management is not jira",
			product:      "jira_service_management",
			vendor:       "atlassian",
			technologies: []string{"Atlassian Jira:10.0"},
		},
		{
			name:         "jquery family name is not jquery",
			product:      "jquery-bbq",
			vendor:       "jquery-bbq_project",
			technologies: []string{"jQuery:3.7.0"},
		},
		{
			name:         "wordpress is not microsoft word",
			product:      "wordpress",
			vendor:       "wordpress",
			technologies: []string{"Microsoft Word:16.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := lookupTechVersion(
				tt.product,
				tt.vendor,
				buildTechVersionMap(tt.technologies),
				buildTechnologyVersions(tt.technologies),
			)
			if ok != tt.wantFound || got != tt.want {
				t.Fatalf("lookupTechVersion(%q) = %q, %v; want %q, %v", tt.product, got, ok, tt.want, tt.wantFound)
			}
		})
	}
}

func TestEnrichCPEVersionsIssue2536(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		product      string
		vendor       string
		cpe          string
		technologies []string
		wantCPE      string
	}{
		{
			name:         "liferay portal product name from awesome-search-queries",
			product:      "liferay_portal",
			vendor:       "liferay",
			cpe:          "cpe:2.3:a:liferay:liferay_portal:*:*:*:*:*:*:*:*",
			technologies: []string{"Liferay:7.3.5"},
			wantCPE:      "cpe:2.3:a:liferay:liferay_portal:7.3.5:*:*:*:*:*:*:*",
		},
		{
			name:         "confluence server product name",
			product:      "confluence_server",
			vendor:       "atlassian",
			cpe:          "cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*",
			technologies: []string{"Confluence:8.5.1"},
			wantCPE:      "cpe:2.3:a:atlassian:confluence_server:8.5.1:*:*:*:*:*:*:*",
		},
		{
			name:         "tableau server product name",
			product:      "tableau_server",
			vendor:       "tableau",
			cpe:          "cpe:2.3:a:tableau:tableau_server:*:*:*:*:*:*:*:*",
			technologies: []string{"Tableau:2023.1"},
			wantCPE:      "cpe:2.3:a:tableau:tableau_server:2023.1:*:*:*:*:*:*:*",
		},
		{
			name:         "no false match on unrelated substring",
			product:      "phpcollab",
			vendor:       "phpcollab",
			cpe:          "cpe:2.3:a:phpcollab:phpcollab:*:*:*:*:*:*:*:*",
			technologies: []string{"PHP:8.1.0"},
			wantCPE:      "cpe:2.3:a:phpcollab:phpcollab:*:*:*:*:*:*:*:*",
		},
		{
			name:         "ansible tower strips suffix",
			product:      "ansible_tower",
			vendor:       "redhat",
			cpe:          "cpe:2.3:a:redhat:ansible_tower:*:*:*:*:*:*:*:*",
			technologies: []string{"Ansible:2.14.0"},
			wantCPE:      "cpe:2.3:a:redhat:ansible_tower:2.14.0:*:*:*:*:*:*:*",
		},
		{
			name:         "ansible policy manager prefers ansible alias",
			product:      "ansible_policy_manager",
			vendor:       "redhat",
			cpe:          "cpe:2.3:a:redhat:ansible_policy_manager:*:*:*:*:*:*:*:*",
			technologies: []string{"Ansible:2.14.0"},
			wantCPE:      "cpe:2.3:a:redhat:ansible_policy_manager:2.14.0:*:*:*:*:*:*:*",
		},
		{

			name:         "conflicting tech versions leave cpe unchanged",
			product:      "liferay_portal",
			vendor:       "liferay",
			cpe:          "cpe:2.3:a:liferay:liferay_portal:*:*:*:*:*:*:*:*",
			technologies: []string{"Liferay:7.3.5", "Liferay:7.4.0"},
			wantCPE:      "cpe:2.3:a:liferay:liferay_portal:*:*:*:*:*:*:*:*",
		},
		{
			// #2550: wappalyzer's display name carries a vendor prefix
			// ("Apache Tomcat") that awesome-search-queries' bare CPE
			// product name ("tomcat") doesn't. Resolved by the whole-word
			// token fallback in lookupTechVersion.
			name:         "vendor-prefixed wappalyzer name matches bare CPE product (#2550)",
			product:      "tomcat",
			vendor:       "apache",
			cpe:          "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
			technologies: []string{"Apache Tomcat:9.0.65"},
			wantCPE:      "cpe:2.3:a:apache:tomcat:9.0.65:*:*:*:*:*:*:*",
		},
		{
			// Reverse case: a narrow alias bridges the CPE product "d3.js" to
			// wappalyzer's short display name without weakening token guards.
			name:         "bare wappalyzer name matches suffixed CPE product (#2550)",
			product:      "d3.js",
			vendor:       "d3.js_project",
			cpe:          "cpe:2.3:a:d3.js_project:d3.js:*:*:*:*:*:*:*:*",
			technologies: []string{"D3:7.8.5"},
			wantCPE:      "cpe:2.3:a:d3.js_project:d3.js:7.8.5:*:*:*:*:*:*:*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := []CPEInfo{{Product: tt.product, Vendor: tt.vendor, CPE: tt.cpe}}
			got := EnrichCPEVersions(matches, tt.technologies)
			if got[0].CPE != tt.wantCPE {
				t.Fatalf("CPE = %q, want %q", got[0].CPE, tt.wantCPE)
			}
		})
	}
}

func TestBuildTechVersionMapConflict(t *testing.T) {
	// the same product reported with two versions must be dropped, not resolved
	// by random map iteration order.
	techs := []string{"Foo:1.2.3", "Foo:1.2.4", "Bar:9.0"}
	got := buildTechVersionMap(techs)

	if _, ok := got["foo"]; ok {
		t.Fatalf("conflicting product foo should be dropped, got %q", got["foo"])
	}
	if got["bar"] != "9.0" {
		t.Fatalf("got[bar] = %q, want 9.0", got["bar"])
	}
}

func TestEnrichCPEVersions(t *testing.T) {
	matches := []CPEInfo{
		{Product: "next.js", Vendor: "vercel", CPE: "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"},
		{Product: "Apache HTTP Server", Vendor: "apache", CPE: "cpe:2.3:a:apache:apache_http_server:*:*:*:*:*:*:*:*"},
		{Product: "Bootstrap", Vendor: "getbootstrap", CPE: "cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*"},
		// awesome-search-queries reports this product as snake_case while
		// wappalyzer reports the display name "WebLogic Server"; normalization
		// must still join them.
		{Product: "weblogic_server", Vendor: "oracle", CPE: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*"},
	}
	technologies := []string{"Next.js:14.2.3", "Apache HTTP Server:2.4.7", "Bootstrap", "WebLogic Server:12.2.1"}

	got := EnrichCPEVersions(matches, technologies)

	// issue #2476: next.js version is injected
	if got[0].CPE != "cpe:2.3:a:vercel:next.js:14.2.3:*:*:*:*:*:*:*" {
		t.Fatalf("next.js CPE = %q, want version 14.2.3 injected", got[0].CPE)
	}
	// case-insensitive product match works for multi-word names
	if got[1].CPE != "cpe:2.3:a:apache:apache_http_server:2.4.7:*:*:*:*:*:*:*" {
		t.Fatalf("apache CPE = %q, want version 2.4.7 injected", got[1].CPE)
	}
	// no detected version -> unchanged (still '*')
	if got[2].CPE != "cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*" {
		t.Fatalf("bootstrap CPE = %q, want unchanged", got[2].CPE)
	}
	// snake_case product joins display-name technology via normalization
	if got[3].CPE != "cpe:2.3:a:oracle:weblogic_server:12.2.1:*:*:*:*:*:*:*" {
		t.Fatalf("weblogic CPE = %q, want version 12.2.1 injected", got[3].CPE)
	}
	// input must not be mutated (immutability)
	if matches[0].CPE != "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*" {
		t.Fatalf("input matches[0] was mutated: %q", matches[0].CPE)
	}
}

// TestEnrichCPEVersionsWithRealWappalyzer exercises the full contract the
// feature depends on end-to-end: a real wappalyzer fingerprint must yield
// "Name:version" technology entries (FormatAppVersion convention) that
// EnrichCPEVersions can parse and inject. This guards the integration the
// count-only functional test cannot assert.
func TestEnrichCPEVersionsWithRealWappalyzer(t *testing.T) {
	wappalyze, err := wappalyzer.New()
	if err != nil {
		t.Fatalf("could not create wappalyzer: %s", err)
	}

	// liferay-portal header carries a version; wappalyzer reports "Liferay:7.3.5".
	info := wappalyze.FingerprintWithInfo(map[string][]string{
		"liferay-portal": {"testserver 7.3.5"},
	}, nil)

	var technologies []string
	for name := range info {
		technologies = append(technologies, name)
	}
	if !sliceContains(technologies, "Liferay:7.3.5") {
		t.Fatalf("expected wappalyzer to emit \"Liferay:7.3.5\", got %v", technologies)
	}

	// awesome-search-queries uses snake_case product names; issue #2536.
	matches := []CPEInfo{
		{Product: "liferay_portal", Vendor: "liferay", CPE: "cpe:2.3:a:liferay:liferay_portal:*:*:*:*:*:*:*:*"},
	}
	got := EnrichCPEVersions(matches, technologies)
	if got[0].CPE != "cpe:2.3:a:liferay:liferay_portal:7.3.5:*:*:*:*:*:*:*" {
		t.Fatalf("liferay CPE = %q, want version 7.3.5 injected end-to-end", got[0].CPE)
	}
}

func TestEnrichTomcatCPEWithRealDatasets(t *testing.T) {
	wappalyze, err := wappalyzer.New()
	if err != nil {
		t.Fatalf("could not create wappalyzer: %s", err)
	}

	info := wappalyze.FingerprintWithInfo(map[string][]string{
		"x-powered-by": {"Tomcat-9.0.65"},
	}, nil)
	var technologies []string
	for name := range info {
		technologies = append(technologies, name)
	}
	if !sliceContains(technologies, "Apache Tomcat:9.0.65") {
		t.Fatalf("expected real wappalyzer data to emit Apache Tomcat:9.0.65, got %v", technologies)
	}

	detector, err := NewCPEDetector()
	if err != nil {
		t.Fatalf("could not create CPE detector: %s", err)
	}
	matches := detector.Detect("", "Apache Tomcat", "")
	var found bool
	for _, match := range EnrichCPEVersions(matches, technologies) {
		if match.Product != "tomcat" {
			continue
		}
		found = true
		want := "cpe:2.3:a:apache:tomcat:9.0.65:*:*:*:*:*:*:*"
		if match.CPE != want {
			t.Fatalf("Tomcat CPE = %q, want %q", match.CPE, want)
		}
	}
	if !found {
		t.Fatalf("real awesome-search-queries data did not detect the Tomcat product; matches: %v", matches)
	}
}

func TestEnrichVendorPrefixedTechnologiesIndependently(t *testing.T) {
	matches := []CPEInfo{
		{
			Product: "tomcat",
			Vendor:  "apache",
			CPE:     "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
		},
		{
			Product: "http_server",
			Vendor:  "apache",
			CPE:     "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
		},
	}
	technologies := []string{
		"Apache Tomcat:9.0.65",
		"Apache HTTP Server:2.4.62",
	}

	got := EnrichCPEVersions(matches, technologies)
	want := []string{
		"cpe:2.3:a:apache:tomcat:9.0.65:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*",
	}
	for i := range want {
		if got[i].CPE != want[i] {
			t.Fatalf("CPE[%d] = %q, want %q", i, got[i].CPE, want[i])
		}
	}
}

func sliceContains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

func TestEnrichCPEVersionsNoTechnologies(t *testing.T) {
	matches := []CPEInfo{
		{Product: "next.js", Vendor: "vercel", CPE: "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"},
	}
	got := EnrichCPEVersions(matches, nil)
	if got[0].CPE != matches[0].CPE {
		t.Fatalf("with no technologies CPE should be unchanged, got %q", got[0].CPE)
	}
	// the early-return path must still return a copy: mutating the result
	// must not reach back into the caller's input slice.
	got[0].CPE = "mutated"
	if matches[0].CPE == "mutated" {
		t.Fatalf("early-return aliased the input slice; want a copy")
	}
}
