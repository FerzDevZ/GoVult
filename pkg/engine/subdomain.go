package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

func BruteSubdomains(domain string, wordlist []string) []string {
	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Worker Pool for Subdomains
	concurrency := 10
	semaphore := make(chan struct{}, concurrency)

	fmt.Printf("[SUBDOMAIN] Brute-forcing subdomains for %s (%d words)\n", domain, len(wordlist))

	for _, word := range wordlist {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fullDomain := sub + "." + domain
			_, err := net.LookupHost(fullDomain)
			if err == nil {
				mu.Lock()
				results = append(results, fullDomain)
				mu.Unlock()
				fmt.Printf("    - [FOUND] %s\n", fullDomain)
			}
		}(strings.TrimSpace(word))
	}

	wg.Wait()
	return results
}

type CrtResult struct {
	NameValue string `json:"common_name"`
}

func PassiveDiscovery(domain string) []string {
	fmt.Printf("[RECON] Performing passive subdomain discovery for %s via crt.sh...\n", domain)
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var crtResults []CrtResult
	if err := json.Unmarshal(body, &crtResults); err != nil {
		return nil
	}

	unique := make(map[string]bool)
	var subdomains []string
	for _, res := range crtResults {
		sub := strings.ToLower(res.NameValue)
		if !unique[sub] && strings.HasSuffix(sub, domain) {
			unique[sub] = true
			subdomains = append(subdomains, sub)
			fmt.Printf("    - [PASSIVE] Found: %s\n", sub)
		}
	}

	return subdomains
}
