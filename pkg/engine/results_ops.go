package engine

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

type Baseline struct {
	Findings map[string]Result `json:"findings"`
}

func ResultKey(r Result) string {
	return strings.ToLower(strings.TrimSpace(r.TemplateID)) + "::" + strings.TrimSpace(r.Target)
}

func DeduplicateResults(results []Result) []Result {
	unique := make(map[string]Result, len(results))
	for _, r := range results {
		key := ResultKey(r)
		existing, ok := unique[key]
		if !ok || rankConfidence(r.Confidence) > rankConfidence(existing.Confidence) {
			unique[key] = r
		}
	}
	out := make([]Result, 0, len(unique))
	for _, r := range unique {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity == out[j].Severity {
			return out[i].TemplateID < out[j].TemplateID
		}
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	return out
}

func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Findings == nil {
		b.Findings = map[string]Result{}
	}
	return &b, nil
}

func SaveBaseline(path string, results []Result) error {
	b := Baseline{Findings: make(map[string]Result, len(results))}
	for _, r := range results {
		b.Findings[ResultKey(r)] = r
	}
	blob, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o644)
}

func NewFindingsOnly(results []Result, baseline *Baseline) []Result {
	if baseline == nil || len(baseline.Findings) == 0 {
		return results
	}
	var out []Result
	for _, r := range results {
		if _, exists := baseline.Findings[ResultKey(r)]; !exists {
			out = append(out, r)
		}
	}
	return out
}

func CalculateConfidence(r Result) string {
	score := 0
	if r.Verified {
		score += 3
	}
	if r.Exploited {
		score += 3
	}
	if strings.TrimSpace(r.Evidence) != "" {
		score++
	}
	if r.Status >= 200 && r.Status < 500 {
		score++
	}
	switch strings.ToLower(r.Severity) {
	case "critical", "high":
		score++
	}

	switch {
	case score >= 6:
		return "high"
	case score >= 3:
		return "medium"
	default:
		return "low"
	}
}

func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func rankConfidence(c string) int {
	switch strings.ToLower(c) {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
