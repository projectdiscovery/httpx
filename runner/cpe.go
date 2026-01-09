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
