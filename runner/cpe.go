package runner

import (
	"encoding/json"
	"fmt"
	"strings"

	awesomesearchqueries "github.com/projectdiscovery/awesome-search-queries"
)

type CPEInfo struct {
	Product string `json:"product,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

type CPEDetector struct {
	titlePatterns   map[string][]CPEInfo
	bodyPatterns    map[string][]CPEInfo
	faviconPatterns map[string][]CPEInfo
}

type rawQuery struct {
	Name    string          `json:"name"`
	Vendor  json.RawMessage `json:"vendor"`
	Type    string          `json:"type"`
	Engines []rawEngine     `json:"engines"`
}

type rawEngine struct {
	Platform string   `json:"platform"`
	Queries  []string `json:"queries"`
}

func NewCPEDetector() (*CPEDetector, error) {
	data, err := awesomesearchqueries.GetQueries()
	if err != nil {
		return nil, fmt.Errorf("failed to load queries: %w", err)
	}

	var queries []rawQuery
	if err := json.Unmarshal(data, &queries); err != nil {
		return nil, fmt.Errorf("failed to parse queries: %w", err)
	}

	detector := &CPEDetector{
		titlePatterns:   make(map[string][]CPEInfo),
		bodyPatterns:    make(map[string][]CPEInfo),
		faviconPatterns: make(map[string][]CPEInfo),
	}

	for _, q := range queries {
		vendor := parseVendor(q.Vendor)
		info := CPEInfo{
			Product: q.Name,
			Vendor:  vendor,
			CPE:     generateCPE(vendor, q.Name),
		}

		for _, engine := range q.Engines {
			for _, query := range engine.Queries {
				detector.extractPattern(query, info)
			}
		}
	}

	return detector, nil
}

func parseVendor(raw json.RawMessage) string {
	var vendorStr string
	if err := json.Unmarshal(raw, &vendorStr); err == nil {
		return vendorStr
	}

	var vendorSlice []string
	if err := json.Unmarshal(raw, &vendorSlice); err == nil && len(vendorSlice) > 0 {
		return vendorSlice[0]
	}

	return ""
}

func generateCPE(vendor, product string) string {
	if vendor == "" || product == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*",
		strings.ToLower(strings.ReplaceAll(vendor, " ", "_")),
		strings.ToLower(strings.ReplaceAll(product, " ", "_")))
}

// techDetectRequired reports whether tech-detect must run: JSON/CSV output,
// asset upload, and -cpe (which reuses detected versions) all consume the
// technology list.
func techDetectRequired(options *Options) bool {
	return options.TechDetect ||
		options.JSONOutput ||
		options.CSVOutput ||
		options.AssetUpload ||
		options.CPEDetect
}

// cpeVersionFieldIndex is the zero-based position of the version field in a
// CPE 2.3 formatted string: cpe:2.3:<part>:<vendor>:<product>:<version>:...
const cpeVersionFieldIndex = 5

// cpeFieldCount is the exact number of colon-separated fields in a well-formed
// CPE 2.3 string: cpe, 2.3, part, vendor, product, version, update, edition,
// language, sw_edition, target_sw, target_hw, other.
const cpeFieldCount = 13

// sanitizeCPEVersion normalizes a detected version for embedding in a CPE
// string: trim surrounding space and replace inner spaces with underscores.
// Case is preserved — CPE 2.3 matching is case-insensitive, and lowercasing
// would corrupt semantically meaningful identifiers like 1.0.0-RC1 or 9.0.0.M1.
func sanitizeCPEVersion(version string) string {
	return strings.ReplaceAll(strings.TrimSpace(version), " ", "_")
}

// setCPEVersion returns a copy of a CPE 2.3 string with its version field
// replaced. The input is returned unchanged if version/cpe is empty or the CPE
// is malformed.
func setCPEVersion(cpe, version string) string {
	version = sanitizeCPEVersion(version)
	if cpe == "" || version == "" {
		return cpe
	}
	// Reserved CPE 2.3 chars (':' field separator, '*'/'?' wildcards) would
	// corrupt the field layout or matching semantics; leave the CPE unenriched.
	if strings.ContainsAny(version, ":*?") {
		return cpe
	}
	parts := strings.Split(cpe, ":")
	if len(parts) != cpeFieldCount || parts[0] != "cpe" || parts[1] != "2.3" {
		return cpe
	}
	parts[cpeVersionFieldIndex] = version
	return strings.Join(parts, ":")
}

// normalizeProductName reduces a product/technology name to its lowercase
// alphanumeric form so the two independent datasets can be joined. The CPE
// product names (awesome-search-queries) are mostly snake_case
// (e.g. "weblogic_server") while wappalyzer reports display names
// (e.g. "WebLogic Server"); stripping every non-alphanumeric rune lets those
// align. It is strictly more permissive than a lower+trim compare, so it never
// drops a previously matching pair, only adds new ones.
func normalizeProductName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	return b.String()
}

// buildTechVersionMap maps normalized technology name -> version, parsing
// wappalyzer's "Name:version" entries (FormatAppVersion convention). Entries
// without a version are skipped. A product reported with conflicting versions
// is dropped rather than resolved by map iteration order, which is random.
func buildTechVersionMap(technologies []string) map[string]string {
	versions := make(map[string]string, len(technologies))
	conflicting := make(map[string]struct{})
	for _, tech := range technologies {
		parts := strings.SplitN(tech, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := normalizeProductName(parts[0])
		version := strings.TrimSpace(parts[1])
		if name == "" || version == "" {
			continue
		}
		if _, ok := conflicting[name]; ok {
			continue
		}
		if existing, ok := versions[name]; ok && existing != version {
			delete(versions, name)
			conflicting[name] = struct{}{}
			continue
		}
		versions[name] = version
	}
	return versions
}

// EnrichCPEVersions returns a copy of matches with each CPE version field
// filled from a matching detected technology, keyed by normalized product name
// (see normalizeProductName). Unmatched products keep their '*' version. Inputs
// are not mutated.
func EnrichCPEVersions(matches []CPEInfo, technologies []string) []CPEInfo {
	if len(matches) == 0 || len(technologies) == 0 {
		return append([]CPEInfo(nil), matches...)
	}
	versions := buildTechVersionMap(technologies)

	enriched := make([]CPEInfo, len(matches))
	for i, match := range matches {
		enriched[i] = match
		if version, ok := versions[normalizeProductName(match.Product)]; ok {
			enriched[i].CPE = setCPEVersion(match.CPE, version)
		}
	}
	return enriched
}

func (d *CPEDetector) extractPattern(query string, info CPEInfo) {
	query = strings.TrimSpace(query)

	titlePrefixes := []string{
		"http.title:",
		"title=",
		"title==",
		"intitle:",
		"title:",
		"title='",
		`title="`,
	}

	for _, prefix := range titlePrefixes {
		if strings.HasPrefix(strings.ToLower(query), strings.ToLower(prefix)) {
			pattern := extractQuotedValue(strings.TrimPrefix(query, prefix))
			pattern = strings.TrimPrefix(pattern, prefix[:len(prefix)-1])
			if pattern != "" {
				pattern = strings.ToLower(pattern)
				d.titlePatterns[pattern] = appendUnique(d.titlePatterns[pattern], info)
			}
			return
		}
	}

	bodyPrefixes := []string{
		"http.html:",
		"body=",
		"body==",
		"intext:",
	}

	for _, prefix := range bodyPrefixes {
		if strings.HasPrefix(strings.ToLower(query), strings.ToLower(prefix)) {
			pattern := extractQuotedValue(strings.TrimPrefix(query, prefix))
			if pattern != "" {
				pattern = strings.ToLower(pattern)
				d.bodyPatterns[pattern] = appendUnique(d.bodyPatterns[pattern], info)
			}
			return
		}
	}

	faviconPrefixes := []string{
		"http.favicon.hash:",
		"icon_hash=",
		"icon_hash==",
	}

	for _, prefix := range faviconPrefixes {
		if strings.HasPrefix(strings.ToLower(query), strings.ToLower(prefix)) {
			pattern := extractQuotedValue(strings.TrimPrefix(query, prefix))
			if pattern != "" {
				d.faviconPatterns[pattern] = appendUnique(d.faviconPatterns[pattern], info)
			}
			return
		}
	}
}

func extractQuotedValue(s string) string {
	s = strings.TrimSpace(s)

	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
		}
	}

	if idx := strings.Index(s, "\" ||"); idx > 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "' ||"); idx > 0 {
		s = s[:idx]
	}

	return strings.TrimSpace(s)
}

func appendUnique(slice []CPEInfo, info CPEInfo) []CPEInfo {
	for _, existing := range slice {
		if existing.Product == info.Product && existing.Vendor == info.Vendor {
			return slice
		}
	}
	return append(slice, info)
}

func (d *CPEDetector) Detect(title, body, faviconHash string) []CPEInfo {
	seen := make(map[string]bool)
	var results []CPEInfo

	titleLower := strings.ToLower(title)
	bodyLower := strings.ToLower(body)

	for pattern, infos := range d.titlePatterns {
		if strings.Contains(titleLower, pattern) {
			for _, info := range infos {
				key := info.Product + "|" + info.Vendor
				if !seen[key] {
					seen[key] = true
					results = append(results, info)
				}
			}
		}
	}

	for pattern, infos := range d.bodyPatterns {
		if strings.Contains(bodyLower, pattern) {
			for _, info := range infos {
				key := info.Product + "|" + info.Vendor
				if !seen[key] {
					seen[key] = true
					results = append(results, info)
				}
			}
		}
	}

	if faviconHash != "" {
		if infos, ok := d.faviconPatterns[faviconHash]; ok {
			for _, info := range infos {
				key := info.Product + "|" + info.Vendor
				if !seen[key] {
					seen[key] = true
					results = append(results, info)
				}
			}
		}
	}

	return results
}
