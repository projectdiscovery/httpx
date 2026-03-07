package runner

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	awesomesearchqueries "github.com/projectdiscovery/awesome-search-queries"
)

type WordPressInfo struct {
	Plugins []string `json:"plugins,omitempty"`
	Themes  []string `json:"themes,omitempty"`
}

type WordPressDetector struct {
	knownPlugins map[string]struct{}
	knownThemes  map[string]struct{}
	pluginRegex  *regexp.Regexp
	themeRegex   *regexp.Regexp
}

func NewWordPressDetector() (*WordPressDetector, error) {
	detector := &WordPressDetector{
		knownPlugins: make(map[string]struct{}),
		knownThemes:  make(map[string]struct{}),
	}

	var err error

	detector.pluginRegex, err = regexp.Compile(`/wp-content/plugins/([a-zA-Z0-9_-]+)/`)
	if err != nil {
		return nil, err
	}

	detector.themeRegex, err = regexp.Compile(`/wp-content/themes/([a-zA-Z0-9_-]+)/`)
	if err != nil {
		return nil, err
	}

	pluginsData, err := awesomesearchqueries.GetWordPressPlugins()
	if err != nil {
		return nil, err
	}
	if err := detector.loadList(pluginsData, detector.knownPlugins); err != nil {
		return nil, err
	}

	themesData, err := awesomesearchqueries.GetWordPressThemes()
	if err != nil {
		return nil, err
	}
	if err := detector.loadList(themesData, detector.knownThemes); err != nil {
		return nil, err
	}

	return detector, nil
}

func (d *WordPressDetector) loadList(data []byte, target map[string]struct{}) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			target[line] = struct{}{}
		}
	}
	return scanner.Err()
}

func (d *WordPressDetector) Detect(body string) *WordPressInfo {
	if body == "" {
		return nil
	}

	info := &WordPressInfo{}
	seenPlugins := make(map[string]struct{})
	seenThemes := make(map[string]struct{})

	if matches := d.pluginRegex.FindAllStringSubmatch(body, -1); len(matches) > 0 {
		for _, match := range matches {
			if len(match) > 1 {
				plugin := match[1]
				if _, seen := seenPlugins[plugin]; !seen {
					if _, known := d.knownPlugins[plugin]; known {
						info.Plugins = append(info.Plugins, plugin)
						seenPlugins[plugin] = struct{}{}
					}
				}
			}
		}
	}

	if matches := d.themeRegex.FindAllStringSubmatch(body, -1); len(matches) > 0 {
		for _, match := range matches {
			if len(match) > 1 {
				theme := match[1]
				if _, seen := seenThemes[theme]; !seen {
					if _, known := d.knownThemes[theme]; known {
						info.Themes = append(info.Themes, theme)
						seenThemes[theme] = struct{}{}
					}
				}
			}
		}
	}

	if len(info.Plugins) == 0 && len(info.Themes) == 0 {
		return nil
	}

	return info
}

func (w *WordPressInfo) HasData() bool {
	return w != nil && (len(w.Plugins) > 0 || len(w.Themes) > 0)
}
