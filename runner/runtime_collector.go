package runner

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/rod"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// The collection logic mirrors wappalyzergo's headless collector. That package
// takes a go-rod page, which cannot be the projectdiscovery/rod page httpx uses,
// so the same evidence batch is collected here through the runtimePage seam.

const (
	maxRuntimeExternalScripts = 25
	maxRuntimeScriptLength    = 500_000
)

// runtimePage is the browser surface the collector needs. The rod adapter
// implements it, and tests replace it with a fake.
type runtimePage interface {
	Evaluate(ctx context.Context, script string, argument interface{}, result interface{}) error
	GetResource(ctx context.Context, url string) ([]byte, error)
}

type rodRuntimePage struct {
	page *rod.Page
}

func (p rodRuntimePage) Evaluate(ctx context.Context, script string, argument interface{}, result interface{}) error {
	remoteObject, err := p.page.Context(ctx).Eval(script, argument)
	if err != nil {
		return err
	}
	if err := remoteObject.Value.Unmarshal(result); err != nil {
		return fmt.Errorf("decode browser result: %w", err)
	}
	return nil
}

func (p rodRuntimePage) GetResource(ctx context.Context, url string) ([]byte, error) {
	return p.page.Context(ctx).GetResource(url)
}

// runtimeCollector implements wappalyzer.RuntimeCollector on a caller-owned page.
type runtimeCollector struct {
	page runtimePage
}

var _ wappalyzer.RuntimeCollector = (*runtimeCollector)(nil)

// newRuntimeCollector wraps a rod page. The caller keeps ownership of the page.
func newRuntimeCollector(page *rod.Page) *runtimeCollector {
	if page == nil {
		return &runtimeCollector{}
	}
	return &runtimeCollector{page: rodRuntimePage{page: page}}
}

// Collect evaluates JavaScript properties, DOM rules and inline scripts in one
// page call, then reads the external script resources it was told about.
func (c *runtimeCollector) Collect(ctx context.Context, rules wappalyzer.RuntimeRules) (wappalyzer.RuntimeEvidence, error) {
	if c == nil || c.page == nil {
		return wappalyzer.RuntimeEvidence{}, fmt.Errorf("collect runtime evidence: page is nil")
	}
	if ctx == nil {
		return wappalyzer.RuntimeEvidence{}, fmt.Errorf("collect runtime evidence: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return wappalyzer.RuntimeEvidence{}, err
	}

	var collected runtimeBrowserEvidence
	if err := c.page.Evaluate(ctx, collectRuntimeEvidenceScript, rules, &collected); err != nil {
		return wappalyzer.RuntimeEvidence{}, fmt.Errorf("evaluate page runtime: %w", err)
	}

	evidence := wappalyzer.RuntimeEvidence{
		JavaScriptProperties: collected.JavaScriptProperties,
		DOM:                  collected.DOM,
		Scripts:              collected.Scripts,
	}
	if !rules.Scripts {
		return evidence, nil
	}

	seen := make(map[string]struct{}, len(collected.ScriptURLs))
	for _, url := range collected.ScriptURLs {
		if len(seen) >= maxRuntimeExternalScripts {
			break
		}
		if _, ok := seen[url]; ok {
			continue
		}
		seen[url] = struct{}{}

		if err := ctx.Err(); err != nil {
			return evidence, err
		}
		content, err := c.page.GetResource(ctx, url)
		if err != nil {
			// The browser cache does not keep every resource. Missing optional
			// script content is absence of evidence, not a failed batch.
			continue
		}
		if len(content) > maxRuntimeScriptLength {
			content = content[:maxRuntimeScriptLength]
		}
		if len(content) > 0 {
			evidence.Scripts = append(evidence.Scripts, string(content))
		}
	}

	return evidence, nil
}

type runtimeBrowserEvidence struct {
	JavaScriptProperties map[string]string                        `json:"javascriptProperties"`
	DOM                  map[string]wappalyzer.RuntimeDOMEvidence `json:"dom"`
	Scripts              []string                                 `json:"scripts"`
	ScriptURLs           []string                                 `json:"scriptURLs"`
}

// collectRuntimeEvidenceScript receives the rule set as its argument. Rule
// strings are data and are never evaluated as source code.
const collectRuntimeEvidenceScript = `(rules) => {
  const maxValues = 50
  const maxValueLength = 1000000
  const maxScripts = 25
  const maxScriptLength = 500000

  const map = () => Object.create(null)

  const scalar = (value) => {
    if (typeof value === 'string') return value.slice(0, maxValueLength)
    if (typeof value === 'number' || typeof value === 'bigint' || typeof value === 'boolean') return String(value)
    return String(Boolean(value))
  }

  const addValue = (values, key, value) => {
    if (!Object.prototype.hasOwnProperty.call(values, key)) values[key] = []
    if (values[key].length < maxValues && !values[key].includes(value)) values[key].push(value)
  }

  const javascriptProperties = map()
  for (const chain of rules.javascriptProperties || []) {
    const parts = chain.split('.')
    let value = window
    let found = true

    if (parts[0] === 'window') parts.shift()

    for (const part of parts) {
      if (
        value === null ||
        (typeof value !== 'object' && typeof value !== 'function') ||
        !Object.prototype.hasOwnProperty.call(value, part)
      ) {
        found = false
        break
      }

      try {
        value = value[part]
      } catch (_) {
        found = false
        break
      }
    }

    if (found && typeof value !== 'undefined') javascriptProperties[chain] = scalar(value)
  }

  const dom = map()
  for (const rule of rules.dom || []) {
    let nodes
    try {
      nodes = document.querySelectorAll(rule.selector)
    } catch (_) {
      continue
    }
    if (!nodes.length) continue

    const observed = { exists: true }
    if (rule.text) observed.text = []
    if ((rule.attributes || []).length) observed.attributes = map()
    if ((rule.properties || []).length) observed.properties = map()

    if (!rule.text && !(rule.attributes || []).length && !(rule.properties || []).length) {
      dom[rule.selector] = observed
      continue
    }

    for (const node of nodes) {
      if (rule.text && observed.text.length < maxValues) {
        const text = (node.textContent || '').trim().slice(0, maxValueLength)
        if (text && !observed.text.includes(text)) observed.text.push(text)
      }

      for (const attribute of rule.attributes || []) {
        if (node.hasAttribute(attribute)) addValue(observed.attributes, attribute, scalar(node.getAttribute(attribute)))
      }

      for (const property of rule.properties || []) {
        if (!Object.prototype.hasOwnProperty.call(node, property)) continue
        try {
          const value = node[property]
          if (typeof value !== 'undefined') addValue(observed.properties, property, scalar(value))
        } catch (_) {
          // Continue with the next property.
        }
      }
    }

    dom[rule.selector] = observed
  }

  const scripts = []
  const scriptURLs = []
  if (rules.scripts) {
    for (const node of Array.from(document.scripts)) {
      const script = (node.textContent || '').slice(0, maxScriptLength)
      if (script && scripts.length < maxScripts && !scripts.includes(script)) scripts.push(script)
      if (
        node.src &&
        !node.src.startsWith('data:') &&
        scriptURLs.length < maxScripts &&
        !scriptURLs.includes(node.src)
      ) scriptURLs.push(node.src)
    }
  }

  return { javascriptProperties, dom, scripts, scriptURLs }
}`
