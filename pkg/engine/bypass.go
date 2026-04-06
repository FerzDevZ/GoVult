package engine

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BypassResult stores findings regarding WAF bypass
type BypassResult struct {
	OriginIP string
	Method   string // "SSL-Match", "DNS-History", "Subdomain"
	Verified bool
}

// FindOrigin attempts to find the real IP address of a target protected by WAF/CDN
func (e *Engine) FindOrigin(target string) (*BypassResult, error) {
	u, _ := url.Parse(target)
	domain := u.Host
	fmt.Printf("[BYPASS] Searching for origin IP of %s...\n", domain)

	// 1. SSL Certificate matching via crt.sh (Passive)
	// This is a simplified version: we look for subdomains that might point to the same origin
	subdomains := PassiveDiscovery(domain)
	for _, sub := range subdomains {
		// vX: OOB Detection (Interactions)
		if e.OOB != nil && strings.Contains(sub, "blind") {
			oobURL, correlationID := e.OOB.GenerateURL()
			fmt.Printf("    [OOB] Generated tracking URL: %s (ID: %s)\n", oobURL, correlationID)
		}
		if strings.HasPrefix(sub, "direct.") || strings.HasPrefix(sub, "origin.") || strings.HasPrefix(sub, "dev.") {
			fmt.Printf("    [!] Found potential origin subdomain: %s\n", sub)
			ip, err := e.verifyOrigin(target, sub)
			if err == nil {
				return &BypassResult{OriginIP: ip, Method: "Subdomain-Match", Verified: true}, nil
			}
		}
	}

	// 2. SSL/TLS Certificate serial matching (Theoretical - requires Censys or similar)
	// For this manual implementation, we'll suggest manual verification or use a common IP range scan
	
	return nil, fmt.Errorf("origin IP not found")
}

func (e *Engine) verifyOrigin(target, originHost string) (string, error) {
	// Compare response of target vs direct originHost
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Get baseline
	resp1, err := client.Get(target)
	if err != nil { return "", err }
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)

	// Get origin probe
	req2, _ := http.NewRequest("GET", "http://"+originHost, nil)
	targetURL, _ := url.Parse(target)
	req2.Host = targetURL.Host // Set Host header to bypass potential SNI issues on origin
	resp2, err := client.Do(req2)
	if err != nil { return "", err }
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	// Simple heuristic: status and body length similarity
	if resp1.StatusCode == resp2.StatusCode && len(body1) == len(body2) {
		fmt.Printf("    [+] Origin Verified: %s\n", originHost)
		return originHost, nil
	}

	return "", fmt.Errorf("not origin")
}
