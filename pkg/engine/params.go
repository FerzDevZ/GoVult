package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Common hidden parameters often used for debugging or admin bypass
var HiddenParams = []string{
	"debug", "dev", "test", "admin", "config", "shell", "cmd", "exec", 
	"root", "internal", "source", "file", "path", "url", "redirect", 
	"callback", "token", "apiKey", "secret", "user_id", "bypass",
}

// DiscoverParams brute-forces hidden URL parameters
func (e *Engine) DiscoverParams(target string) ([]string, error) {
	var found []string
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	// Identify baseline response for comparison
	baselineCode, baselineLen := e.getBaseline(target)

	for _, p := range HiddenParams {
		e.Limiter.Wait(context.Background())
		
		testURL := target
		if strings.Contains(target, "?") {
			testURL += "&" + p + "=1"
		} else {
			testURL += "?" + p + "=1"
		}

		resp, err := e.Client.Get(testURL)
		if err != nil { continue }
		defer resp.Body.Close()

		// If status code or response length significantly changes, it's a hit
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != baselineCode || len(body) != baselineLen {
			found = append(found, p)
			fmt.Printf("    [+] Hidden Parameter Found: %s\n", p)
		}
	}

	return found, nil
}

func (e *Engine) getBaseline(target string) (int, int) {
	resp, err := e.Client.Get(target)
	if err != nil { return 0, 0 }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, len(body)
}
