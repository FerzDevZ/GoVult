package engine

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type FuzzResult struct {
	Path       string
	StatusCode int
}

type FuzzerOptions struct {
	MaxDepth    int
	Concurrency int
}

func Fuzz(target string, wordlist []string, options FuzzerOptions) ([]FuzzResult, error) {
	var results []FuzzResult
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Internal helper for recursion
	var recursiveFuzz func(currentURL string, depth int)
	recursiveFuzz = func(currentURL string, depth int) {
		if depth > options.MaxDepth {
			return
		}

		for _, path := range wordlist {
			url := strings.TrimSuffix(currentURL, "/") + "/" + strings.TrimPrefix(path, "/")
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				fmt.Printf("[FUZZ] Found: %s (%d)\n", url, resp.StatusCode)
				results = append(results, FuzzResult{
					Path:       url,
					StatusCode: resp.StatusCode,
				})

				// If directory found (status 200/403 often indicates dir/file), try to go deeper
				// Basic check for dir (no extension or ends with /)
				if resp.StatusCode == 200 && !strings.Contains(path, ".") {
					recursiveFuzz(url, depth+1)
				}
			}
		}
	}

	recursiveFuzz(target, 0)
	return results, nil
}
