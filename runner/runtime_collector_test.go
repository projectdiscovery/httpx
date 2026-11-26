package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// fakeRuntimePage replays canned evidence and serves script resources from a map.
type fakeRuntimePage struct {
	evidence     runtimeBrowserEvidence
	evaluateErr  error
	resources    map[string][]byte
	evaluateRuns int
	fetched      []string
}

func (f *fakeRuntimePage) Evaluate(_ context.Context, _ string, _ interface{}, result interface{}) error {
	f.evaluateRuns++
	if f.evaluateErr != nil {
		return f.evaluateErr
	}
	raw, err := json.Marshal(f.evidence)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, result)
}

func (f *fakeRuntimePage) GetResource(_ context.Context, url string) ([]byte, error) {
	f.fetched = append(f.fetched, url)
	content, ok := f.resources[url]
	if !ok {
		return nil, fmt.Errorf("resource %s not cached", url)
	}
	return content, nil
}

func TestRuntimeCollectorDecodesEvidence(t *testing.T) {
	page := &fakeRuntimePage{evidence: runtimeBrowserEvidence{
		JavaScriptProperties: map[string]string{"window.jQuery.fn.jquery": "3.7.1"},
		DOM: map[string]wappalyzer.RuntimeDOMEvidence{
			"meta[name=generator]": {Exists: true, Attributes: map[string][]string{"content": {"WordPress 6.5"}}},
		},
		Scripts:    []string{"inline()"},
		ScriptURLs: []string{"https://cdn.example/app.js"},
	}}
	collector := &runtimeCollector{page: page}

	evidence, err := collector.Collect(context.Background(), wappalyzer.RuntimeRules{})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got := evidence.JavaScriptProperties["window.jQuery.fn.jquery"]; got != "3.7.1" {
		t.Fatalf("javascript property = %q, want 3.7.1", got)
	}
	if !evidence.DOM["meta[name=generator]"].Exists {
		t.Fatalf("DOM selector not decoded: %+v", evidence.DOM)
	}
	if len(evidence.Scripts) != 1 || evidence.Scripts[0] != "inline()" {
		t.Fatalf("inline scripts = %v, want [inline()]", evidence.Scripts)
	}
	if len(page.fetched) != 0 {
		t.Fatalf("external scripts fetched without rules.Scripts: %v", page.fetched)
	}
}

func TestRuntimeCollectorFetchesDedupedScriptsWithLimit(t *testing.T) {
	var urls []string
	resources := map[string][]byte{}
	for i := 0; i < 30; i++ {
		u := fmt.Sprintf("https://cdn.example/%d.js", i)
		urls = append(urls, u, u) // duplicates must be skipped
		resources[u] = []byte("x")
	}
	// Resource errors are absence of evidence, not a failed batch.
	delete(resources, "https://cdn.example/3.js")
	big := strings.Repeat("a", maxRuntimeScriptLength+10)
	resources["https://cdn.example/0.js"] = []byte(big)

	page := &fakeRuntimePage{evidence: runtimeBrowserEvidence{ScriptURLs: urls}, resources: resources}
	collector := &runtimeCollector{page: page}

	evidence, err := collector.Collect(context.Background(), wappalyzer.RuntimeRules{Scripts: true})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(page.fetched) != maxRuntimeExternalScripts {
		t.Fatalf("fetched %d resources, want %d", len(page.fetched), maxRuntimeExternalScripts)
	}
	seen := map[string]bool{}
	for _, u := range page.fetched {
		if seen[u] {
			t.Fatalf("resource %s fetched twice", u)
		}
		seen[u] = true
	}
	if len(evidence.Scripts) == 0 || len(evidence.Scripts[0]) != maxRuntimeScriptLength {
		t.Fatalf("oversized script not truncated to %d", maxRuntimeScriptLength)
	}
}

func TestRuntimeCollectorPropagatesEvaluateError(t *testing.T) {
	boom := errors.New("eval failed")
	collector := &runtimeCollector{page: &fakeRuntimePage{evaluateErr: boom}}

	_, err := collector.Collect(context.Background(), wappalyzer.RuntimeRules{})
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want wrapped %v", err, boom)
	}
}

func TestRuntimeCollectorRejectsNilPageAndCanceledContext(t *testing.T) {
	if _, err := newRuntimeCollector(nil).Collect(context.Background(), wappalyzer.RuntimeRules{}); err == nil {
		t.Fatal("nil page did not return an error")
	}

	page := &fakeRuntimePage{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&runtimeCollector{page: page}).Collect(ctx, wappalyzer.RuntimeRules{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v, want context.Canceled", err)
	}
	if page.evaluateRuns != 0 {
		t.Fatal("page was evaluated after the context was canceled")
	}
}

func TestValidateOptionsRuntimeRequiresTechDetect(t *testing.T) {
	options := &Options{TechDetectRuntime: true}
	err := options.ValidateOptions()
	if err == nil || !strings.Contains(err.Error(), "requires -td") {
		t.Fatalf("ValidateOptions error = %v, want a -td requirement", err)
	}
}
