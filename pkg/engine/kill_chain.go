package engine

import (
	"fmt"
	"io"
	"strings"
)

// RunKillChain orchestrates multi-step attacks based on YAML definitions
func (e *Engine) RunKillChain(target string, findings []Result) []Result {
	fmt.Printf("[KILL-CHAIN] Orchestrating automated multi-step attacks for: %s...\n", target)
	var additionalFindings []Result

	chains, err := LoadChains("chains")
	if err != nil {
		fmt.Printf("    [!] Error loading chains: %v\n", err)
		return nil
	}

	for _, res := range findings {
		for _, chain := range chains {
			match := false
			for _, cond := range chain.Condition {
				if strings.Contains(strings.ToLower(res.TemplateID), strings.ToLower(cond)) {
					match = true
					break
				}
			}

			if match {
				fmt.Printf("    [CHAIN] %s (%s)\n", chain.ID, chain.Description)
				vars := make(map[string]string)
				
				for i, step := range chain.Steps {
					e.Wait()
					
					// Replace variables in path and body
					finalPath := step.Path[0] // Use first path for now
					for k, v := range vars {
						finalPath = strings.ReplaceAll(finalPath, "{{"+k+"}}", v)
					}
					
					u := target + finalPath
					resChain, body, resp, _ := e.scanSingleWithBody(u, step.Method, step.Headers, step.Body, step.Matchers, nil)
					
					if resChain != nil {
						fmt.Printf("        [STEP %d] Success: %s\n", i+1, u)
						
						// Extract variables
						for _, ext := range step.Extractors {
							val := Extract(body, resp.Header, ext)
							if val != "" {
								vars[ext.Name] = val
								fmt.Printf("        [EXTRACT] %s = %s\n", ext.Name, val)
							}
						}

						// If it's the last step and we matched, record it
						if i == len(chain.Steps)-1 {
							additionalFindings = append(additionalFindings, Result{
								TemplateID: chain.ID,
								Target:     u,
								Evidence:   fmt.Sprintf("Chained attack success via: %s", chain.ID),
								Verified:   true,
							})
						}
					} else {
						fmt.Printf("        [STEP %d] Failed for %s\n", i+1, u)
						break // Chain broken
					}
				}
			}
		}
	}

	return additionalFindings
}
