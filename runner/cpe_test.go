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

	matches := []CPEInfo{
		{Product: "Liferay", Vendor: "liferay", CPE: "cpe:2.3:a:liferay:liferay_portal:*:*:*:*:*:*:*:*"},
	}
	got := EnrichCPEVersions(matches, technologies)
	if got[0].CPE != "cpe:2.3:a:liferay:liferay_portal:7.3.5:*:*:*:*:*:*:*" {
		t.Fatalf("liferay CPE = %q, want version 7.3.5 injected end-to-end", got[0].CPE)
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
