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
	fmt.Printf("[RECON] Performing multi-source passive discovery for %s...\n", domain)
	unique := make(map[string]bool)
	var subdomains []string

	sources := []struct {
		name string
		url  string
	}{
		{"crt.sh", "https://crt.sh/?q=%.domain&output=json"},
		{"RapidDNS", "https://rapiddns.io/subdomain/domain?full=1"},
		{"HackerTarget", "https://api.hackertarget.com/hostsearch/?q=domain"},
	}

	for _, s := range sources {
		u := strings.ReplaceAll(s.url, "domain", domain)
		resp, err := http.Get(u)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		switch s.name {
		case "crt.sh":
			var crtResults []CrtResult
			json.Unmarshal(body, &crtResults)
			for _, res := range crtResults {
				addIfUnique(res.NameValue, domain, unique, &subdomains)
			}
		case "RapidDNS":
			// Simple regex for rapiddns.io
			re := regexp.MustCompile(`<td>([a-z0-9.-]+\.`+domain+`)</td>`)
			matches := re.FindAllStringSubmatch(string(body), -1)
			for _, m := range matches {
				addIfUnique(m[1], domain, unique, &subdomains)
			}
		case "HackerTarget":
			lines := strings.Split(string(body), "\n")
			for _, line := range lines {
				parts := strings.Split(line, ",")
				if len(parts) > 0 {
					addIfUnique(parts[0], domain, unique, &subdomains)
				}
			}
		}
		fmt.Printf("    - [RECON] Source %s completed.\n", s.name)
	}

	return subdomains
}

func addIfUnique(sub, domain string, unique map[string]bool, results *[]string) {
	sub = strings.ToLower(strings.TrimSpace(sub))
	if sub == "" || strings.HasPrefix(sub, "*.") {
		return
	}
	if !unique[sub] && strings.HasSuffix(sub, domain) {
		unique[sub] = true
		*results = append(*results, sub)
		fmt.Printf("    - [FOUND] %s\n", sub)
	}
}
