package engine

import (
	"fmt"
	"time"
)

// ParamDiver mining hidden parameters for unauthorized access
func (e *Engine) ParamDiver(target string) []string {
	fmt.Printf("[PARAM-DIVER] Mining hidden parameters via behavioral diffing...\n")
	var foundParams []string

	// Common hidden parameters
	params := []string{"debug", "admin", "test", "dev", "v", "cfg", "show", "internal"}

	// 1. Get baseline (Normal Response)
	resp1, err := e.Client.Get(target)
	if err != nil {
		return nil
	}
	defer resp1.Body.Close()
	baselineLen := resp1.ContentLength

	// 2. Probe each parameter
	for _, p := range params {
		u := fmt.Sprintf("%s?%s=1", target, p)
		resp2, err := e.Client.Get(u)
		if err != nil { continue }
		defer resp2.Body.Close()

		// 3. Behavioral Diffing (Length changes + Header changes)
		if resp2.ContentLength != baselineLen || resp2.StatusCode != resp1.StatusCode {
			fmt.Printf("    [!] Found hidden parameter: %s (Behavioral change detected!)\n", p)
			foundParams = append(foundParams, p)
		}
		time.Sleep(100 * time.Millisecond) // throttling
	}

	return foundParams
}
