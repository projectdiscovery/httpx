package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
	_ "github.com/projectdiscovery/httpx/statik"
	"github.com/rakyll/statik/fs"
	"net/http"
	"regexp"
	"strings"
)

// StringArray type is a wrapper for []string for use in unmarshalling the technologies.json
type StringArray []string

// UnmarshalJSON is a custom unmarshaler for handling bogus technologies.json types from wappalyzer
func (t *StringArray) UnmarshalJSON(data []byte) error {
	var s string
	var sa []string
	var na []int

	if err := json.Unmarshal(data, &s); err != nil {
		if err := json.Unmarshal(data, &na); err == nil {
			// not a string, so maybe []int?
			*t = make(StringArray, len(na))

			for i, number := range na {
				(*t)[i] = fmt.Sprintf("%d", number)
			}

			return nil
		} else if err := json.Unmarshal(data, &sa); err == nil {
			// not a string, so maybe []string?
			*t = sa
			return nil
		}
		//fmt.Println(string(data)) // for debug
		return err
	}
	*t = StringArray{s}
	return nil
}

// App type encapsulates all the data about an App from technologies.json
type App struct {
	Cats    StringArray            `json:"cats"`
	Cookies map[string]string      `json:"cookies"`
	Headers map[string]string      `json:"headers"`
	Meta    map[string]StringArray `json:"meta"`
	HTML    StringArray            `json:"html"`
	Script  StringArray            `json:"scripts"`
	URL     StringArray            `json:"url"`
	Website string                 `json:"website"`
	Implies StringArray            `json:"implies"`

	HTMLRegex   []AppRegexp `json:"-"`
	ScriptRegex []AppRegexp `json:"-"`
	URLRegex    []AppRegexp `json:"-"`
	HeaderRegex []AppRegexp `json:"-"`
	MetaRegex   []AppRegexp `json:"-"`
	CookieRegex []AppRegexp `json:"-"`
}

// Category names defined by wappalyzer
type Category struct {
	Name string `json:"name"`
}

type AppsDefinition struct {
	Apps map[string]App      `json:"technologies"`
	Cats map[string]Category `json:"categories"`
}

type FingerPrint struct {
	appDefs *AppsDefinition
}
type Findings struct {
	app     App
	appName string
}
type AppRegexp struct {
	Name   string
	Regexp *regexp.Regexp
}

func (fp *FingerPrint) Init() {
	statikFS, err := fs.New()
	if err != nil {
		gologger.Fatalf("err: %v\n", err.Error())
	}
	fi, err := statikFS.Open("/technologies.json")
	if err != nil {
		gologger.Fatalf(err.Error())
	}
	defer fi.Close()
	dec := json.NewDecoder(fi)
	if err := dec.Decode(&fp.appDefs); err != nil {
		gologger.Fatalf(err.Error())
	}
	for key, value := range fp.appDefs.Apps {
		app := fp.appDefs.Apps[key]
		app.HTMLRegex = compileRegexes(value.HTML)
		app.ScriptRegex = compileRegexes(value.Script)
		app.URLRegex = compileRegexes(value.URL)

		app.HeaderRegex = compileNamedRegexes(app.Headers)
		app.CookieRegex = compileNamedRegexes(app.Cookies)

		// handle special meta field where value can be a list
		// of strings. we join them as a simple regex here
		metaRegex := make(map[string]string)
		for k, v := range app.Meta {
			metaRegex[k] = strings.Join(v, "|")
		}
		app.MetaRegex = compileNamedRegexes(metaRegex)
		fp.appDefs.Apps[key] = app
	}
}
func (fp *FingerPrint) Fingerprint(r *Response, url string) ([]string, error) {
	body := r.Raw
	headers := r.Headers
	cookies := r.Cookie
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(r.Data))
	if err != nil {
		return []string{}, errors.New("goquery faild")
	}

	findings := []Findings{}
	result := []string{}
	rset := make(map[string]struct{}) // New empty set

	for appName, app := range fp.appDefs.Apps {

		// check raw html
		for _, regx := range app.HTMLRegex {
			if regx.Regexp.MatchString(body) {
				findings = append(findings, Findings{app, appName})
			}
		}

		// check header
		for _, regx := range app.HeaderRegex {
			hk := http.CanonicalHeaderKey(regx.Name)
			if _, ok := headers[hk]; !ok {
				continue
			}
			for _, headerValue := range headers[hk] {
				if headerValue == "" {
					continue
				}
				if regx.Regexp.MatchString(headerValue) {
					findings = append(findings, Findings{app, appName})
				}
			}
		}

		// check url
		for _, regx := range app.URLRegex {
			if regx.Regexp.MatchString(url) {
				findings = append(findings, Findings{app, appName})
			}
		}

		// check script tags
		doc.Find("script").Each(func(i int, s *goquery.Selection) {
			if script, exists := s.Attr("src"); exists {
				for _, regx := range app.ScriptRegex {
					if regx.Regexp.MatchString(script) {
						findings = append(findings, Findings{app, appName})
					}
				}
			}
		})

		// check meta tags
		for _, regx := range app.MetaRegex {
			doc.Find(fmt.Sprintf("meta[name='%s']", regx.Name)).Each(func(i int, s *goquery.Selection) {
				content, _ := s.Attr("content")
				if regx.Regexp.MatchString(content) {
					findings = append(findings, Findings{app, appName})
				}
			})
		}

		// check cookies
		for _, c := range app.CookieRegex {
			if _, ok := cookies[c.Name]; ok {
				// if there is a regexp set, ensure it matches.
				// otherwise just add this as a match
				if c.Regexp != nil {
					if c.Regexp.MatchString(cookies[c.Name]) {
						findings = append(findings, Findings{app, appName})
					}
				} else {
					findings = append(findings, Findings{app, appName})
				}
			}

		}
	}
	if len(findings) > 0 {
		for _, finding := range findings {
			rset[finding.appName] = struct{}{}
			// handle implies
			for _, implies := range finding.app.Implies {
				implies = strings.Split(implies, "\\;")[0]
				rset[implies] = struct{}{}
			}
		}
	}
	for appName := range rset {
		result = append(result, appName)
	}
	return result, nil
}

func compileRegexes(s StringArray) []AppRegexp {
	var list []AppRegexp

	for _, regexString := range s {

		// Split version detection
		splitted := strings.Split(regexString, "\\;")

		regex, err := regexp.Compile(splitted[0])
		if err != nil {
			// ignore failed compiling for now
			// log.Printf("warning: compiling regexp for failed: %v", regexString, err)
		} else {
			rv := AppRegexp{
				Regexp: regex,
			}
			list = append(list, rv)
		}
	}

	return list
}
func compileNamedRegexes(from map[string]string) []AppRegexp {

	var list []AppRegexp

	for key, value := range from {

		h := AppRegexp{
			Name: key,
		}

		if value == "" {
			value = ".*"
		}

		// Filter out webapplyzer attributes from regular expression
		splitted := strings.Split(value, "\\;")

		r, err := regexp.Compile(splitted[0])
		if err != nil {
			continue
		}
		h.Regexp = r
		list = append(list, h)
	}

	return list
}
