package engine

import (
	"fmt"
	"net/http"
	"time"
)

type FuzzResult struct {
	Path       string
	StatusCode int
}

func Fuzz(target string, wordlist []string) ([]FuzzResult, error) {
	var results []FuzzResult
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, path := range wordlist {
		url := target + "/" + path
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
		}
	}

	return results, nil
}
