package engine

import (
	"html/template"
	"os"
	"time"
)

type ReportData struct {
	Target    string
	Findings  []Result
	ScanTime  string
	RiskScore int
}

func GenerateHTML(target string, findings []Result, outputPath string) error {
	data := ReportData{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now().Format("2006-01-02 15:04:05"),
	}

	// Calculate Risk Score (Basic logic: 2 points for critical, 1 for high, 0.5 for medium)
	var score float32
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			score += 2
		case "high":
			score += 1
		case "medium":
			score += 0.5
		}
	}
	if score > 10 {
		score = 10
	}
	data.RiskScore = int(score)

	tmpl, err := template.New("report").Parse(ReportTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}
