package engine

import (
	"encoding/json"
	"os"
	"time"
)

type JSONReport struct {
	Target    string   `json:"target"`
	Timestamp string   `json:"timestamp"`
	Count     int      `json:"count"`
	Results   []Result `json:"results"`
}

func GenerateJSON(target string, results []Result, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	payload := JSONReport{
		Target:    target,
		Timestamp: time.Now().Format(time.RFC3339),
		Count:     len(results),
		Results:   results,
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func GenerateSARIF(results []Result, filename string) error {
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}

	levelFor := func(sev string) string {
		switch sev {
		case "critical", "high":
			return "error"
		case "medium":
			return "warning"
		default:
			return "note"
		}
	}

	sarifResults := make([]sarifResult, 0, len(results))
	for _, r := range results {
		item := sarifResult{
			RuleID: r.TemplateID,
			Level:  levelFor(r.Severity),
		}
		item.Message.Text = r.Description
		loc := struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		}{}
		loc.PhysicalLocation.ArtifactLocation.URI = r.Target
		item.Locations = append(item.Locations, loc)
		sarifResults = append(sarifResults, item)
	}

	doc := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "GoVult",
						"informationUri": "https://github.com/FerzDevZ/GoVult",
					},
				},
				"results": sarifResults,
			},
		},
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
