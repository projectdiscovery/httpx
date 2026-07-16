package httpx

import (
	"bytes"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/PuerkitoBio/goquery"
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

const (
	potentialDomainRegex = `(?:^|['"/@])` + `([a-z0-9]+[a-z0-9.-]*\.[a-z]{2,})` + `(?:['"/@]|$)`
)

var (
	potentialDomainsCompiled = regexp.MustCompile(potentialDomainRegex)
	defaultDenylist          = []string{".3g2", ".3gp", ".7z", ".apk", ".arj", ".avi", ".axd", ".bmp", ".csv", ".deb", ".dll", ".doc", ".drv", ".eot", ".exe", ".flv", ".gif", ".gifv", ".gz", ".h264", ".ico", ".iso", ".jar", ".jpeg", ".jpg", ".lock", ".m4a", ".m4v", ".map", ".mkv", ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".msi", ".ogg", ".ogm", ".ogv", ".otf", ".pdf", ".pkg", ".png", ".ppt", ".psd", ".rar", ".rm", ".rpm", ".svg", ".swf", ".sys", ".tar.gz", ".tar", ".tif", ".tiff", ".ttf", ".txt", ".vob", ".wav", ".webm", ".webp", ".wmv", ".woff", ".woff2", ".xcf", ".xls", ".xlsx", ".zip", ".css", ".js", ".map", ".php", ".sheet", ".ms", ".wp", ".html", ".htm", ".md"}
	suffixBlacklist          = map[string]struct{}{}

	urlAttrs = []string{"href", "src", "action", "formaction", "poster", "cite", "data-url", "data-href"}

	maxInlineScriptSize = 512 * 1024 // skip JS AST parsing for scripts larger than 512KB
)

type BodyDomain struct {
	Fqdns   []string `json:"body_fqdn,omitempty"`
	Domains []string `json:"body_domains,omitempty"`
}

func (h *HTTPX) BodyDomainGrab(r *Response) *BodyDomain {
	domains := make(map[string]struct{})
	fqdns := make(map[string]struct{})

	if len(r.Data) > 0 {
		switch {
		case looksLikeHTML(r.Data):
			inlineScripts := extractDomainsFromHTML(r.Data, domains, fqdns, r.Input)
			for _, script := range inlineScripts {
				if len(script) <= maxInlineScriptSize {
					extractDomainsFromJS(script, domains, fqdns, r.Input)
				}
			}
		case looksLikeJavaScript(r.Data, r.GetHeader("Content-Type")):
			if len(r.Data) <= maxInlineScriptSize {
				extractDomainsFromJS(string(r.Data), domains, fqdns, r.Input)
			} else {
				extractDomainsFromRegex(string(r.Data), domains, fqdns, r.Input)
			}
		default:
			extractDomainsFromRegex(r.Raw, domains, fqdns, r.Input)
		}
	} else {
		extractDomainsFromRegex(r.Raw, domains, fqdns, r.Input)
	}

	return &BodyDomain{Domains: mapsutil.GetKeys(domains), Fqdns: mapsutil.GetKeys(fqdns)}
}

func looksLikeHTML(data []byte) bool {
	trimmed := trimmedBodyPrefix(data)
	return len(trimmed) > 0 && trimmed[0] == '<'
}

func looksLikeJavaScript(data []byte, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}

	trimmed := trimmedBodyPrefix(data)
	if len(trimmed) == 0 {
		return false
	}

	s := string(trimmed)
	return strings.HasPrefix(s, "var ") ||
		strings.HasPrefix(s, "const ") ||
		strings.HasPrefix(s, "let ") ||
		strings.HasPrefix(s, "function") ||
		strings.HasPrefix(s, "(function") ||
		strings.HasPrefix(s, "/*") ||
		strings.HasPrefix(s, "//") ||
		strings.HasPrefix(s, "import ") ||
		strings.HasPrefix(s, "export ") ||
		strings.HasPrefix(s, "!") ||
		strings.HasPrefix(s, "\"use strict\"") ||
		strings.HasPrefix(s, "'use strict'")
}

func trimmedBodyPrefix(data []byte) []byte {
	prefix := data
	if len(prefix) > 1024 {
		prefix = prefix[:1024]
	}
	trimmed := bytes.TrimSpace(prefix)
	return bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF})
}

func inputHostname(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(input); err == nil {
		return host
	}
	return input
}

// extractDomainsFromHTML parses HTML and extracts hostnames from URL-bearing
// attributes (href, src, action, etc.), meta tags, and srcset values.
// It returns the text content of inline <script> tags for downstream JS parsing.
func extractDomainsFromHTML(data []byte, domains, fqdns map[string]struct{}, input string) []string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}

	var inlineScripts []string

	// URL-bearing attributes
	for _, attr := range urlAttrs {
		doc.Find("[" + attr + "]").Each(func(_ int, s *goquery.Selection) {
			if val, exists := s.Attr(attr); exists {
				if host := hostnameFromURL(val); host != "" {
					addDomainCandidate(host, domains, fqdns, input)
				}
			}
		})
	}

	// srcset contains comma-separated "url size" pairs
	doc.Find("[srcset]").Each(func(_ int, s *goquery.Selection) {
		if val, exists := s.Attr("srcset"); exists {
			for _, entry := range strings.Split(val, ",") {
				parts := strings.Fields(strings.TrimSpace(entry))
				if len(parts) > 0 {
					if host := hostnameFromURL(parts[0]); host != "" {
						addDomainCandidate(host, domains, fqdns, input)
					}
				}
			}
		}
	})

	// <meta> content attributes (open graph, canonical hints, etc.)
	doc.Find("meta[content]").Each(func(_ int, s *goquery.Selection) {
		content, exists := s.Attr("content")
		if !exists {
			return
		}
		if host := hostnameFromURL(content); host != "" {
			addDomainCandidate(host, domains, fqdns, input)
		}
		// <meta http-equiv="refresh" content="0;url=https://...">
		if httpEquiv, _ := s.Attr("http-equiv"); strings.EqualFold(httpEquiv, "refresh") {
			if idx := strings.Index(strings.ToLower(content), "url="); idx >= 0 {
				refreshURL := strings.TrimSpace(content[idx+4:])
				if host := hostnameFromURL(refreshURL); host != "" {
					addDomainCandidate(host, domains, fqdns, input)
				}
			}
		}
	})

	// Collect inline <script> text for JS AST parsing or regex extraction
	doc.Find("script").Each(func(_ int, s *goquery.Selection) {
		if _, hasSrc := s.Attr("src"); hasSrc {
			return
		}
		text := strings.TrimSpace(s.Text())
		if text == "" {
			return
		}
		scriptType, _ := s.Attr("type")
		if strings.EqualFold(scriptType, "application/ld+json") || strings.EqualFold(scriptType, "application/json") {
			// JSON blocks can't be parsed by goja; extract domains via regex
			extractDomainsFromRegex(text, domains, fqdns, input)
		} else {
			inlineScripts = append(inlineScripts, text)
		}
	})

	return inlineScripts
}

// extractDomainsFromJS parses JavaScript using goja's AST parser and extracts
// domain candidates from string literals and template literal elements.
func extractDomainsFromJS(script string, domains, fqdns map[string]struct{}, input string) {
	program, err := parser.ParseFile(nil, "", script, 0)
	if err != nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	walkProgram(program, func(value string) {
		for _, match := range potentialDomainsCompiled.FindAllStringSubmatch(value, -1) {
			if len(match) >= 2 {
				addDomainCandidate(match[1], domains, fqdns, input)
			}
		}
		if host := hostnameFromURL(value); host != "" {
			addDomainCandidate(host, domains, fqdns, input)
		}
	})
}

// extractDomainsFromRegex applies the original regex-based extraction on raw response text.
func extractDomainsFromRegex(raw string, domains, fqdns map[string]struct{}, input string) {
	for _, tmp := range potentialDomainsCompiled.FindAllStringSubmatch(raw, -1) {
		if len(tmp) < 2 {
			continue
		}
		addDomainCandidate(tmp[1], domains, fqdns, input)
	}
}

// addDomainCandidate validates a candidate domain string and adds it to the
// fqdns/domains maps if it passes all checks.
func addDomainCandidate(d string, domains, fqdns map[string]struct{}, input string) {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimRight(d, ".")
	if d == "" {
		return
	}
	if !isValidDomain(d) {
		return
	}
	if !isValidTLD(d) {
		return
	}
	val, err := publicsuffix.Domain(d)
	if err != nil {
		return
	}
	inputHost := inputHostname(input)
	if inputHost != val {
		domains[val] = struct{}{}
	}
	if d != val && d != inputHost {
		fqdns[d] = struct{}{}
	}
}

func hostnameFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	lowered := strings.ToLower(raw)
	for _, skip := range []string{"#", "javascript:", "data:", "mailto:", "tel:", "blob:", "about:"} {
		if strings.HasPrefix(lowered, skip) {
			return ""
		}
	}
	if !strings.Contains(raw, "://") && !strings.HasPrefix(raw, "//") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" || !strings.Contains(host, ".") {
		return ""
	}
	return host
}

// walkProgram traverses a goja AST program and calls visit for each string
// literal and template literal element value found.
func walkProgram(program *ast.Program, visit func(string)) {
	for _, stmt := range program.Body {
		walkNode(stmt, visit)
	}
}

func walkNode(node ast.Node, visit func(string)) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.StringLiteral:
		visit(n.Value.String())

	case *ast.TemplateLiteral:
		for _, elem := range n.Elements {
			if elem.Parsed.String() != "" {
				visit(elem.Parsed.String())
			}
		}
		for _, expr := range n.Expressions {
			walkNode(expr, visit)
		}

	case *ast.Program:
		for _, s := range n.Body {
			walkNode(s, visit)
		}

	// Statements
	case *ast.BlockStatement:
		for _, s := range n.List {
			walkNode(s, visit)
		}
	case *ast.ExpressionStatement:
		walkNode(n.Expression, visit)
	case *ast.ReturnStatement:
		walkNode(n.Argument, visit)
	case *ast.IfStatement:
		walkNode(n.Test, visit)
		walkNode(n.Consequent, visit)
		walkNode(n.Alternate, visit)
	case *ast.ForStatement:
		walkForLoopInitializer(n.Initializer, visit)
		walkNode(n.Test, visit)
		walkNode(n.Update, visit)
		walkNode(n.Body, visit)
	case *ast.ForInStatement:
		walkForInto(n.Into, visit)
		walkNode(n.Source, visit)
		walkNode(n.Body, visit)
	case *ast.ForOfStatement:
		walkForInto(n.Into, visit)
		walkNode(n.Source, visit)
		walkNode(n.Body, visit)
	case *ast.WhileStatement:
		walkNode(n.Test, visit)
		walkNode(n.Body, visit)
	case *ast.DoWhileStatement:
		walkNode(n.Test, visit)
		walkNode(n.Body, visit)
	case *ast.SwitchStatement:
		walkNode(n.Discriminant, visit)
		for i := range n.Body {
			walkNode(n.Body[i].Test, visit)
			for _, s := range n.Body[i].Consequent {
				walkNode(s, visit)
			}
		}
	case *ast.TryStatement:
		walkNode(n.Body, visit)
		if n.Catch != nil {
			walkNode(n.Catch.Body, visit)
		}
		walkNode(n.Finally, visit)
	case *ast.ThrowStatement:
		walkNode(n.Argument, visit)
	case *ast.WithStatement:
		walkNode(n.Object, visit)
		walkNode(n.Body, visit)
	case *ast.LabelledStatement:
		walkNode(n.Statement, visit)
	case *ast.VariableStatement:
		for _, d := range n.List {
			walkBinding(d, visit)
		}
	case *ast.LexicalDeclaration:
		for _, d := range n.List {
			walkBinding(d, visit)
		}
	case *ast.FunctionDeclaration:
		walkFunctionLiteral(n.Function, visit)
	case *ast.ClassDeclaration:
		walkClassLiteral(n.Class, visit)

	// Expressions
	case *ast.AssignExpression:
		walkNode(n.Left, visit)
		walkNode(n.Right, visit)
	case *ast.BinaryExpression:
		walkNode(n.Left, visit)
		walkNode(n.Right, visit)
	case *ast.UnaryExpression:
		walkNode(n.Operand, visit)
	case *ast.ConditionalExpression:
		walkNode(n.Test, visit)
		walkNode(n.Consequent, visit)
		walkNode(n.Alternate, visit)
	case *ast.CallExpression:
		walkNode(n.Callee, visit)
		for _, arg := range n.ArgumentList {
			walkNode(arg, visit)
		}
	case *ast.NewExpression:
		walkNode(n.Callee, visit)
		for _, arg := range n.ArgumentList {
			walkNode(arg, visit)
		}
	case *ast.DotExpression:
		walkNode(n.Left, visit)
	case *ast.BracketExpression:
		walkNode(n.Left, visit)
		walkNode(n.Member, visit)
	case *ast.ArrayLiteral:
		for _, v := range n.Value {
			walkNode(v, visit)
		}
	case *ast.ObjectLiteral:
		for _, prop := range n.Value {
			walkPropertyNode(prop, visit)
		}
	case *ast.FunctionLiteral:
		walkFunctionLiteral(n, visit)
	case *ast.ExpressionBody:
		walkNode(n.Expression, visit)
	case *ast.ArrowFunctionLiteral:
		switch body := n.Body.(type) {
		case *ast.BlockStatement:
			walkNode(body, visit)
		case *ast.ExpressionBody:
			walkNode(body.Expression, visit)
		}
	case *ast.ClassLiteral:
		walkClassLiteral(n, visit)
	case *ast.SequenceExpression:
		for _, expr := range n.Sequence {
			walkNode(expr, visit)
		}
	case *ast.SpreadElement:
		walkNode(n.Expression, visit)
	case *ast.YieldExpression:
		walkNode(n.Argument, visit)
	case *ast.AwaitExpression:
		walkNode(n.Argument, visit)
	case *ast.OptionalChain:
		walkNode(n.Expression, visit)
	case *ast.Optional:
		walkNode(n.Expression, visit)
	}
}

func walkForLoopInitializer(init ast.ForLoopInitializer, visit func(string)) {
	if init == nil {
		return
	}
	switch i := init.(type) {
	case *ast.ForLoopInitializerExpression:
		walkNode(i.Expression, visit)
	case *ast.ForLoopInitializerVarDeclList:
		for _, b := range i.List {
			walkBinding(b, visit)
		}
	case *ast.ForLoopInitializerLexicalDecl:
		for _, b := range i.LexicalDeclaration.List {
			walkBinding(b, visit)
		}
	}
}

func walkForInto(into ast.ForInto, visit func(string)) {
	if into == nil {
		return
	}
	switch i := into.(type) {
	case *ast.ForIntoVar:
		walkBinding(i.Binding, visit)
	case *ast.ForIntoExpression:
		walkNode(i.Expression, visit)
	case *ast.ForDeclaration:
		walkNode(i.Target, visit)
	}
}

func walkBinding(b *ast.Binding, visit func(string)) {
	walkNode(b.Target, visit)
	walkNode(b.Initializer, visit)
}

func walkFunctionLiteral(fn *ast.FunctionLiteral, visit func(string)) {
	if fn == nil {
		return
	}
	if fn.Body != nil {
		walkNode(fn.Body, visit)
	}
}

func walkClassLiteral(cls *ast.ClassLiteral, visit func(string)) {
	if cls == nil {
		return
	}
	walkNode(cls.SuperClass, visit)
	for _, elem := range cls.Body {
		switch e := elem.(type) {
		case *ast.FieldDefinition:
			walkNode(e.Key, visit)
			walkNode(e.Initializer, visit)
		case *ast.MethodDefinition:
			walkNode(e.Key, visit)
			walkFunctionLiteral(e.Body, visit)
		case *ast.ClassStaticBlock:
			walkNode(e.Block, visit)
		}
	}
}

func walkPropertyNode(prop ast.Property, visit func(string)) {
	switch p := prop.(type) {
	case *ast.PropertyKeyed:
		walkNode(p.Key, visit)
		walkNode(p.Value, visit)
	case *ast.PropertyShort:
		walkNode(p.Initializer, visit)
	case *ast.SpreadElement:
		walkNode(p.Expression, visit)
	}
}

func isValidDomain(d string) bool {
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return false
	}
	// this is try when all parts are numeric
	// in which this is not a valid domain (could be a ip or something else)
	allnumeric := true
	// traverse in reverse
	for i := len(parts) - 1; i >= 0; i-- {
		if _, ok := suffixBlacklist["."+parts[i]]; ok {
			return false
		}
		// check for numeric
	local:
		for _, c := range parts[i] {
			if !unicode.IsDigit(c) {
				allnumeric = false
				break local
			}
		}
	}

	if allnumeric {
		// not a domain could be ip or something else
		return false
	}

	// simple hack for android/ios package name
	if stringsutil.HasPrefixAny(d, "com", "net", "io", "org") && !stringsutil.HasSuffixAny(d, "com", "net", "io", "org") {
		return false
	}
	return true
}

func isValidTLD(domain string) bool {
	rule := publicsuffix.DefaultList.Find(domain, publicsuffix.DefaultFindOptions)
	if rule == nil || rule.Type != publicsuffix.NormalType {
		return false
	}

	_, err := publicsuffix.ParseFromListWithOptions(publicsuffix.DefaultList, domain, &publicsuffix.FindOptions{DefaultRule: rule})
	return err == nil
}

func init() {
	for _, s := range defaultDenylist {
		suffixBlacklist[s] = struct{}{}
	}
}
