package engine

import (
	"fmt"
	"strings"
)

// MitigationRule represents a virtual patch or remediation advice
type MitigationRule struct {
	VulnType    string
	ModSecRule  string
	NginxRule   string
	FixGuide    map[string]string // Language -> Code snippet
}

// GenerateMitigation creates virtual patches and dev guides based on vulnerability ID
func GenerateMitigation(vulnID string) MitigationRule {
	rule := MitigationRule{
		VulnType: vulnID,
		FixGuide: make(map[string]string),
	}

	if strings.Contains(vulnID, "sqli") {
		rule.ModSecRule = `SecRule ARGS "(?:' OR '1'='1|--|#|UNION SELECT)" "id:1001,phase:2,deny,status:403,msg:'SQL Injection Attempt Detected'"`
		rule.NginxRule = `if ($query_string ~* "UNION.*SELECT") { return 403; }`
		rule.FixGuide["PHP"] = "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$id]);"
		rule.FixGuide["Python"] = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
		rule.FixGuide["Go"] = "db.Query('SELECT * FROM users WHERE id = ?', id)"
	} else if strings.Contains(vulnID, "lfi") || strings.Contains(vulnID, "cve-2024-4956") {
		rule.ModSecRule = `SecRule ARGS "(?:\.\.\/|\/etc\/passwd|\/windows\/win\.ini)" "id:1002,phase:2,deny,status:403,msg:'Path Traversal Attempt Detected'"`
		rule.FixGuide["PHP"] = "$file = basename($_GET['file']);\ninclude('pages/' . $file);"
	} else if strings.Contains(vulnID, "xss") {
		rule.ModSecRule = `SecRule ARGS "(?:<script|alert\(|onerror=)" "id:1003,phase:2,deny,status:403,msg:'XSS Attempt Detected'"`
		rule.FixGuide["JS"] = "const clean = DOMPurify.sanitize(dirty);"
	}

	return rule
}

func (e *Engine) RunMitigationReport(results []Result) string {
	fmt.Printf("[MITIGATION] Generating Virtual Patches and Developer Remediation Guides...\n")
	var report strings.Builder
	report.WriteString("### Cyber-Overlord Mitigation Report\n\n")

	uniqueVulns := make(map[string]bool)
	for _, res := range results {
		if !uniqueVulns[res.TemplateID] {
			uniqueVulns[res.TemplateID] = true
			m := GenerateMitigation(res.TemplateID)
			report.WriteString(fmt.Sprintf("#### Vulnerability: %s\n", res.TemplateID))
			report.WriteString("##### WAF Patch (ModSecurity):\n")
			report.WriteString(fmt.Sprintf("```\n%s\n```\n", m.ModSecRule))
			report.WriteString("##### Developer Fix Guide:\n")
			for lang, code := range m.FixGuide {
				report.WriteString(fmt.Sprintf("- **%s**:\n```%s\n%s\n```\n", lang, strings.ToLower(lang), code))
			}
			report.WriteString("---\n")
		}
	}
	return report.String()
}
