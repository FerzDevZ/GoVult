package engine

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// HoneypotResult represents findings from deception detection
type HoneypotResult struct {
	Type     string
	Evidence string
	Risk     string
}

// DetectHoneypot analyzes server behavior to identify if it's a trap
func (e *Engine) DetectHoneypot(target string) ([]HoneypotResult, error) {
	fmt.Printf("[DECEPTION] Analyzing target behavior for honeypot signatures...\n")
	var results []HoneypotResult

	// 1. Catch-all Detection
	isCatchAll, evidence := e.checkCatchAll(target)
	if isCatchAll {
		results = append(results, HoneypotResult{
			Type:     "Catch-all Response",
			Evidence: evidence,
			Risk:     "High (Potential Lead-in Trap)",
		})
	}

	// 2. Known Header Signatures (e.g. Cowrie/Dionaea)
	hdrRes, _ := e.checkHoneypotHeaders(target)
	if hdrRes != nil {
		results = append(results, *hdrRes)
	}

	return results, nil
}

func (e *Engine) checkCatchAll(target string) (bool, string) {
	rand.Seed(time.Now().UnixNano())
	randomPath := fmt.Sprintf("/vult_%d_%d", rand.Intn(1000), rand.Intn(1000))
	
	resp1, err := e.Client.Get(target + randomPath)
	if err != nil {
		return false, ""
	}
	defer resp1.Body.Close()

	if resp1.StatusCode == 200 {
		// If a random non-existent path returns 200, it's likely a catch-all honeypot
		return true, fmt.Sprintf("Non-existent path %s returned 200 OK.", randomPath)
	}
	return false, ""
}

func (e *Engine) checkHoneypotHeaders(target string) (*HoneypotResult, error) {
	resp, err := e.Client.Get(target)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// Example: Unusual Server headers or specific signatures
	sHeader := resp.Header.Get("Server")
	if strings.Contains(strings.ToLower(sHeader), "cowrie") || 
	   strings.Contains(strings.ToLower(sHeader), "dionaea") {
		return &HoneypotResult{
			Type:     "Honeypot Header Signature",
			Evidence: fmt.Sprintf("Server header: %s", sHeader),
			Risk:     "Critical (Confirmed Trap)",
		}, nil
	}
	return nil, nil
}
