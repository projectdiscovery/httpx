package runner

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
	"sync"

	awesomesearchqueries "github.com/projectdiscovery/awesome-search-queries"
)

type WordPressInfo struct {
	Plugins []string `json:"plugins,omitempty"`
	Themes  []string `json:"themes,omitempty"`
}

type WordPressData struct {
	pluginsMap map[string]struct{}
	themesMap  map[string]struct{}
	sync.Once
	pluginRegex *regexp.Regexp
	themeRegex  *regexp.Regexp
}

func NewWordPressData() (*WordPressData, error) {
	wp := &WordPressData{
		pluginsMap: make(map[string]struct{}),
		themesMap:  make(map[string]struct{}),
	}

	var err error
	wp.pluginRegex, err = regexp.Compile(`/wp-content/plugins/([^/]+)/`)
	if err != nil {
		return nil, err
	}

	wp.themeRegex, err = regexp.Compile(`/wp-content/themes/([^/]+)/`)
	if err != nil {
		return nil, err
	}

	return wp, nil
}

func (w *WordPressData) LoadData() error {
	var err error
	w.Do(func() {
		// Load plugins
		pluginsData, err := awesomesearchqueries.GetWordPressPlugins()
		if err != nil {
			return
		}
		if err = w.loadFromBytes(pluginsData, w.pluginsMap); err != nil {
			return
		}

		// Load themes
		themesData, err := awesomesearchqueries.GetWordPressThemes()
		if err != nil {
			return
		}
		if err = w.loadFromBytes(themesData, w.themesMap); err != nil {
			return
		}
	})
	return err
}

func (w *WordPressData) loadFromBytes(data []byte, dataMap map[string]struct{}) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			dataMap[line] = struct{}{}
		}
	}
	return scanner.Err()
}

func (w *WordPressData) ExtractInfo(body string) *WordPressInfo {
	var info WordPressInfo

	// Extract and validate plugins
	if matches := w.pluginRegex.FindAllStringSubmatch(body, -1); len(matches) > 0 {
		seenPlugins := make(map[string]struct{})
		for _, match := range matches {
			if len(match) > 1 {
				plugin := match[1]
				if _, exists := seenPlugins[plugin]; !exists {
					if _, valid := w.pluginsMap[plugin]; valid {
						info.Plugins = append(info.Plugins, plugin)
						seenPlugins[plugin] = struct{}{}
					}
				}
			}
		}
	}

	// Extract and validate themes
	if matches := w.themeRegex.FindAllStringSubmatch(body, -1); len(matches) > 0 {
		seenThemes := make(map[string]struct{})
		for _, match := range matches {
			if len(match) > 1 {
				theme := match[1]
				if _, exists := seenThemes[theme]; !exists {
					if _, valid := w.themesMap[theme]; valid {
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

	return &info
}
