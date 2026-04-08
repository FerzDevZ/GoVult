package engine

import "testing"

func TestDeduplicateResultsKeepsHigherConfidence(t *testing.T) {
	input := []Result{
		{TemplateID: "xss-reflect", Target: "https://a/path", Confidence: "low", Severity: "medium"},
		{TemplateID: "xss-reflect", Target: "https://a/path", Confidence: "high", Severity: "medium"},
	}

	out := DeduplicateResults(input)
	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}
	if out[0].Confidence != "high" {
		t.Fatalf("expected highest confidence kept, got %s", out[0].Confidence)
	}
}

func TestCalculateConfidence(t *testing.T) {
	r := Result{
		Severity:  "high",
		Verified:  true,
		Exploited: true,
		Evidence:  "proof",
		Status:    200,
	}
	if got := CalculateConfidence(r); got != "high" {
		t.Fatalf("expected high confidence, got %s", got)
	}
}
