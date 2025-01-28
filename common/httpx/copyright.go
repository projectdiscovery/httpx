package httpx

import (
	"regexp"
	"sort"
	"strings"
)

var crreYear = regexp.MustCompile(`(?:copyright|Copyright|COPYRIGHT|\(C\)|\(c\)|©|&copy;|&#169;)?\s*(?:[a-zA-Z0-9 ,-]+\s*)?[\s,]*(199[0-9]|20[0-1][0-9]|202[0-4])[\s,<-]+(?:copyright|Copyright|COPYRIGHT|\(C\)|\(c\)|©|&copy;|&#169;|199[0-9]|20[0-1][0-9]|202[0-4])?`)


func cleanText(text string) string {
    text = strings.ReplaceAll(text, "<span>", "")
    text = strings.ReplaceAll(text, "</span>", "")
    text = strings.ReplaceAll(text, "\u00a0", " ")
    text = strings.ReplaceAll(text, "&#xA9;", "&#169;")
    text = strings.ReplaceAll(text, "–", "-")
    text = strings.ReplaceAll(text, "-->", "")
    text = strings.ReplaceAll(text, "<!--", "")
    return text
}

// ExtractCopyright extracts all copyright dates or years from the raw response body and returns them as a space-delimited string
func ExtractCopyright(resp *Response) string {
	var years []string            // To store all matched years
	var copyrightyears []string   // To store any bonafide copyrights
	var copyrightresults string   // Declare variables outside the blocks
	var yearresults string

	// Convert response data to string and clean it
	textContent := string(resp.Data)
	textContent = cleanText(textContent)


	// Apply regex to extract the years and check for indicators
	matches := crreYear.FindAllStringSubmatch(textContent, -1)
	for _, match := range matches {
		year := strings.TrimSpace(match[1])

		// Check if the year has a copyright indicator around it
		if strings.Contains(match[0], "copyright") || strings.Contains(match[0], "Copyright") || strings.Contains(match[0], "COPYRIGHT") || strings.Contains(match[0], "(C)") || strings.Contains(match[0], "(c)") || strings.Contains(match[0], "©") || strings.Contains(match[0], "&#169;") || strings.Contains(match[0], "&copy;") {
			copyrightyears = append(copyrightyears, year)
		}

		years = append(years, year)
	}

	// If we have any copyrights found, craft our string
	if len(copyrightyears) > 0 {
		// Sort, unique, and flatten our array
		sort.Strings(copyrightyears)

		// Make the years list unique
		uniqueCopyrightYears := make([]string, 0, len(copyrightyears))
		seen := make(map[string]bool)
		for _, copyrightyear := range copyrightyears {
			if !seen[copyrightyear] {
				uniqueCopyrightYears = append(uniqueCopyrightYears, copyrightyear)
				seen[copyrightyear] = true
			}
		}

		green := "\033[32m"
		reset := "\033[0m"
		copyrightresults = "Copyright: " + green + strings.Join(uniqueCopyrightYears, " ") + reset
		return copyrightresults
	}

	if len(years) > 0 {
		sort.Strings(years)

		// Make the years list unique
		uniqueYears := make([]string, 0, len(years))
		seen := make(map[string]bool)
		for _, year := range years {
			if !seen[year] {
				uniqueYears = append(uniqueYears, year)
				seen[year] = true
			}
		}
		yearresults = "Possible Years: " + strings.Join(uniqueYears, " ")
		return yearresults
	}

	return ""
}

