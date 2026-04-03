package engine

import (
	"html/template"
	"os"
	"time"
)

type ReportData struct {
	Target    string
	Timestamp string
	Results   []Result
	Count     int
}

func GenerateHTML(target string, results []Result, filename string) error {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GoVult Enterprise Audit Report</title>
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --text: #f1f5f9;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --accent: #8b5cf6;
        }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 40px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--accent); padding-bottom: 20px; margin-bottom: 40px; }
        .stats { display: flex; gap: 20px; margin-bottom: 40px; }
        .stat-card { background: var(--card); padding: 20px; border-radius: 12px; flex: 1; text-align: center; border: 1px solid #334155; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .vuln-card { background: var(--card); margin-bottom: 20px; border-radius: 12px; overflow: hidden; border: 1px solid #334155; transition: transform 0.2s; }
        .vuln-card:hover { transform: translateY(-5px); border-color: var(--accent); }
        .vuln-header { padding: 20px; display: flex; justify-content: space-between; align-items: center; }
        .severity { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .critical { background: var(--critical); }
        .high { background: var(--high); }
        .medium { background: var(--medium); }
        .low { background: var(--low); }
        .vuln-body { padding: 20px; border-top: 1px solid #334155; background: #0f172a80; }
        .label { font-weight: bold; color: var(--accent); margin-top: 10px; display: block; }
        .remediation { background: #064e3b; color: #6ee7b7; padding: 15px; border-radius: 8px; margin-top: 15px; border-left: 4px solid #10b981; }
        .tag { font-family: monospace; color: #94a3b8; }
        .cvss { font-size: 14px; opacity: 0.8; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>GoVult v6.0</h1>
            <p>Intelligence Audit for: <strong>{{.Target}}</strong></p>
        </div>
        <div style="text-align: right;">
            <p>{{.Timestamp}}</p>
            <p class="tag">Enterprise Intelligence Edition</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{{.Count}}</div>
            <div class="stat-label">Total Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--critical);">{{ .Results | filterVulns "critical" }}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--high);">{{ .Results | filterVulns "high" }}</div>
            <div class="stat-label">High</div>
        </div>
    </div>

    {{range .Results}}
    <div class="vuln-card">
        <div class="vuln-header">
            <div>
                <span class="severity {{.Severity}}">{{.Severity}}</span>
                <span style="font-size: 18px; font-weight: bold; margin-left: 10px;">{{.TemplateID}}</span>
            </div>
            <div class="cvss">CVSS: {{.CVSS}} / 10.0</div>
        </div>
        <div class="vuln-body">
            <span class="label">Target Instance:</span>
            <div class="tag">{{.Target}}</div>
            
            <span class="label">Description:</span>
            <p>{{.Description}}</p>

            <div class="remediation">
                <strong>Remediation Strategy:</strong><br>
                {{.Remediation}}
            </div>
        </div>
    </div>
    {{end}}
</body>
</html>
`
	
	funcMap := template.FuncMap{
		"filterVulns": func(results []Result, sev string) int {
			count := 0
			for _, r := range results {
				if r.Severity == sev {
					count++
				}
			}
			return count
		},
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	data := ReportData{
		Target:    target,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Results:   results,
		Count:     len(results),
	}

	return t.Execute(f, data)
}
