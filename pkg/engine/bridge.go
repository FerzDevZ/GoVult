package engine

import (
	"encoding/json"
	"encoding/xml"
	"os"
)

// ExportToBurp creates a Burp-compatible XML report
func ExportToBurp(results []Result, path string) error {
	type BurpResult struct {
		XMLName     xml.Name `xml:"issues"`
		Target      string   `xml:"target"`
		TemplateID  string   `xml:"type"`
		Severity    string   `xml:"severity"`
		Description string   `xml:"name"`
	}

	var burpRes []BurpResult
	for _, r := range results {
		burpRes = append(burpRes, BurpResult{
			Target:      r.Target,
			TemplateID:  r.TemplateID,
			Severity:    r.Severity,
			Description: r.Description,
		})
	}

	f, _ := os.Create(path)
	defer f.Close()
	enc := xml.NewEncoder(f)
	enc.Indent("  ", "    ")
	return enc.Encode(burpRes)
}

// ExportToZAP creates a ZAP-compatible JSON report
func ExportToZAP(results []Result, path string) error {
	f, _ := os.Create(path)
	defer f.Close()
	return json.NewEncoder(f).Encode(results)
}
