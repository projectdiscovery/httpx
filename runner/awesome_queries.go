package runner

import (
	"encoding/json"
	"strings"

	awesomesearchqueries "github.com/projectdiscovery/awesome-search-queries"
)

type AwesomeQuery struct {
	Name    string    `json:"name"`
	Vendor  string    `json:"vendor"`
	Type    string    `json:"type"`
	Engines []Engines `json:"engines"`
}

type Engines struct {
	Platform string   `json:"platform"`
	Queries  []string `json:"queries"`
}

type AwesomeSearchMaps struct {
	aqTitle   map[string][]ProductVendor
	aqBody    map[string][]ProductVendor
	aqFavicon map[string][]ProductVendor
}

type ProductVendor struct {
	Product string
	Vendor  string
}

func LoadAwesomeQueries() (*AwesomeSearchMaps, error) {
	data, err := awesomesearchqueries.GetQueries()
	if err != nil {
		return nil, err
	}

	var queries []AwesomeQuery
	if err := json.Unmarshal(data, &queries); err != nil {
		return nil, err
	}

	maps := &AwesomeSearchMaps{
		aqTitle:   make(map[string][]ProductVendor),
		aqBody:    make(map[string][]ProductVendor),
		aqFavicon: make(map[string][]ProductVendor),
	}

	for _, query := range queries {
		pv := ProductVendor{
			Product: query.Name,
			Vendor:  query.Vendor,
		}

		for _, engine := range query.Engines {
			for _, q := range engine.Queries {
				switch engine.Platform {
				case "shodan":
					if strings.HasPrefix(q, "http.html:") {
						maps.aqBody[extractQuery(q, "http.html:")] = append(maps.aqBody[extractQuery(q, "http.html:")], pv)
					} else if strings.HasPrefix(q, "http.title:") {
						maps.aqTitle[extractQuery(q, "http.title:")] = append(maps.aqTitle[extractQuery(q, "http.title:")], pv)
					} else if strings.HasPrefix(q, "http.favicon.hash:") {
						maps.aqFavicon[extractQuery(q, "http.favicon.hash:")] = append(maps.aqFavicon[extractQuery(q, "http.favicon.hash:")], pv)
					}
				case "fofa":
					if strings.HasPrefix(q, "body=") {
						maps.aqBody[extractQuery(q, "body=")] = append(maps.aqBody[extractQuery(q, "body=")], pv)
					} else if strings.HasPrefix(q, "title=") {
						maps.aqTitle[extractQuery(q, "title=")] = append(maps.aqTitle[extractQuery(q, "title=")], pv)
					} else if strings.HasPrefix(q, "icon_hash=") {
						maps.aqFavicon[extractQuery(q, "icon_hash=")] = append(maps.aqFavicon[extractQuery(q, "icon_hash=")], pv)
					}
				case "google":
					if strings.HasPrefix(q, "intext:") {
						maps.aqBody[extractQuery(q, "intext:")] = append(maps.aqBody[extractQuery(q, "intext:")], pv)
					} else if strings.HasPrefix(q, "intitle:") {
						maps.aqTitle[extractQuery(q, "intitle:")] = append(maps.aqTitle[extractQuery(q, "intitle:")], pv)
					}
				}
			}
		}
	}

	return maps, nil
}

func extractQuery(query string, prefix string) string {
	q := strings.TrimPrefix(query, prefix)
	return strings.Trim(q, "\"")
}

func (a *AwesomeSearchMaps) FindMatches(result *Result) ([]ProductVendor, bool) {
	var matches []ProductVendor
	matchMap := make(map[string]bool)

	if result.Title != "" {
		for title, pvs := range a.aqTitle {
			if strings.Contains(strings.ToLower(result.Title), strings.ToLower(title)) {
				for _, pv := range pvs {
					key := pv.Product + pv.Vendor
					if !matchMap[key] {
						matches = append(matches, pv)
						matchMap[key] = true
					}
				}
			}
		}
	}

	if result.ResponseBody != "" {
		for body, pvs := range a.aqBody {
			if strings.Contains(strings.ToLower(result.ResponseBody), strings.ToLower(body)) {
				for _, pv := range pvs {
					key := pv.Product + pv.Vendor
					if !matchMap[key] {
						matches = append(matches, pv)
						matchMap[key] = true
					}
				}
			}
		}
	}

	if result.FavIconMMH3 != "" {
		for favicon, pvs := range a.aqFavicon {
			if result.FavIconMMH3 == favicon {
				for _, pv := range pvs {
					key := pv.Product + pv.Vendor
					if !matchMap[key] {
						matches = append(matches, pv)
						matchMap[key] = true
					}
				}
			}
		}
	}

	return matches, len(matches) > 0
}
