package httpx

import (
	"net/http"
	"testing"
)

func TestWave10HeaderCanonicalization(t *testing.T) {
	headers := http.Header{}
	headers.Add("x-bountygrid-trace", "bg-titan-wave10")
	headers.Add("content-type", "application/json")

	val := headers.Get("X-BountyGrid-Trace")
	if val != "bg-titan-wave10" {
		t.Errorf("expected canonical header lookup to match case-insensitively, got %s", val)
	}

	ct := headers.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected canonical Content-Type lookup to match, got %s", ct)
	}
}

func TestWave10StatusCodeClassification(t *testing.T) {
	isSuccess := func(code int) bool {
		return code >= 200 && code < 300
	}
	isRedirect := func(code int) bool {
		return code >= 300 && code < 400
	}

	if !isSuccess(200) || !isSuccess(204) {
		t.Errorf("expected 200/204 to be classified as success")
	}
	if !isRedirect(301) || !isRedirect(308) {
		t.Errorf("expected 301/308 to be classified as redirect")
	}
}
