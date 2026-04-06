package engine

import (
	"fmt"
	"net/http"
	"sync"
)

// GhostProtocol handles automated OOB injection for blind vulnerabilities
func (e *Engine) GhostProtocol(target string) {
	if e.OOB == nil {
		e.OOB = NewOOBClient()
	}

	fmt.Printf("[GHOST] Activating Ghost Protocol: Automated OOB Injection for %s...\n", target)
	oobURL, correlationID := e.OOB.GenerateURL()

	// 1. Blind Header Injection
	headers := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Wap-Profile",
		"Referer",
		"From",
		"Contact",
		"User-Agent",
	}

	var wg sync.WaitGroup
	for _, h := range headers {
		wg.Add(1)
		go func(header string) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", target, nil)
			req.Header.Set(header, oobURL)
			e.Client.Do(req)
		}(h)
	}
	wg.Wait()

	fmt.Printf("    [!] Injected OOB ID: %s into %d headers concurrently. Monitoring for callbacks...\n", correlationID, len(headers))
}

// MonitorGhost waits for OOB interactions
func (e *Engine) MonitorGhost(correlationID string) bool {
	// Simple polling loop
	for i := 0; i < 3; i++ {
		interacted, _ := e.OOB.Poll(correlationID)
		if interacted {
			return true
		}
	}
	return false
}
