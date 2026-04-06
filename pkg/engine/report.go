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
    <title>GoVult Verified Auditor Report</title>
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --text: #f1f5f9;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --accent: #0ea5e9;
            --verified: #10b981;
            --exploited: #f43f5e;
        }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 40px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--accent); padding-bottom: 20px; margin-bottom: 40px; }
        .stats { display: flex; gap: 20px; margin-bottom: 40px; }
        .stat-card { background: var(--card); padding: 20px; border-radius: 12px; flex: 1; text-align: center; border: 1px solid #334155; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .vuln-card { background: var(--card); margin-bottom: 20px; border-radius: 12px; overflow: hidden; border: 1px solid #334155; transition: transform 0.2s; }
        .vuln-card:hover { transform: translateY(-5px); border-color: var(--accent); }
        .vuln-header { padding: 20px; display: flex; justify-content: space-between; align-items: center; }
        .severity { padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .critical { background: var(--critical); }
        .badge-verified { background: var(--verified); color: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 10px; }
        .badge-exploited { background: var(--exploited); color: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 10px; }
        .vuln-body { padding: 20px; border-top: 1px solid #334155; background: #0f172a80; }
        .label { font-weight: bold; color: var(--accent); margin-top: 10px; display: block; }
        .evidence { background: #0c0a09; color: #a8a29e; padding: 15px; border-radius: 8px; margin-top: 15px; border-left: 4px solid var(--verified); font-family: monospace; font-size: 13px; }
        .exploit-proof { background: #1e1b4b; color: #c084fc; padding: 15px; border-radius: 8px; margin-top: 15px; border-left: 4px solid var(--exploited); font-family: monospace; font-size: 13px; white-space: pre-wrap; }
        .remediation { background: #064e3b; color: #6ee7b7; padding: 15px; border-radius: 8px; margin-top: 15px; border-left: 4px solid #10b981; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>GoVult v9.0</h1>
            <p>Verified Auditor Report for: <strong>{{.Target}}</strong></p>
        </div>
        <div style="text-align: right;">
            <p>{{.Timestamp}}</p>
            <p style="color: var(--verified); font-weight: bold;">[ VERIFIED AUDITOR EDITION ]</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{{.Count}}</div>
            <div class="stat-label">Total Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--verified);">{{ .Results | filterVerified }}</div>
            <div class="stat-label">Automatically Verified</div>
        </div>
    </div>

    {{range .Results}}
    <div class="vuln-card">
        <div class="vuln-header">
            <div>
                <span class="severity {{.Severity}}">{{.Severity}}</span>
                {{if .Verified}}<span class="badge-verified">VERIFIED</span>{{end}}
                {{if .Exploited}}<span class="badge-exploited">EXPLOITED</span>{{end}}
                <span style="font-size: 18px; font-weight: bold; margin-left: 10px;">{{.TemplateID}}</span>
            </div>
            <div style="opacity: 0.6; font-size: 13px;">CVSS: {{.CVSS}}</div>
        </div>
        <div class="vuln-body">
            <span class="label">Target Instance:</span>
            <div style="font-family: monospace; color: #94a3b8;">{{.Target}}</div>
            
            {{if .Verified}}
            <span class="label">Audit Evidence:</span>
            <div class="evidence">
                {{.Evidence}}
            </div>
            {{end}}

            {{if .Exploited}}
            <span class="label">Automatic Exploitation Output:</span>
            <div class="exploit-proof">
                {{.ExploitProof}}
            </div>
            {{end}}

            <span class="label">Remediation Advice:</span>
            <div class="remediation">
                {{.Remediation}}
            </div>
        </div>
    </div>
    {{end}}
</body>
</html>
`
	
	funcMap := template.FuncMap{
		"filterVerified": func(results []Result) int {
			count := 0
			for _, r := range results {
				if r.Verified {
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
