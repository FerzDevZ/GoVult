package engine

import (
	"fmt"
	"net"
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
