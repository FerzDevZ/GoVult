package engine

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
)

// DetectPluginVersion extracts version string from readme.txt
func DetectPluginVersion(target, pluginSlug string) string {
	u, _ := url.Parse(target)
	readmeURL := fmt.Sprintf("%s://%s/wp-content/plugins/%s/readme.txt", u.Scheme, u.Host, pluginSlug)
	
	resp, err := http.Get(readmeURL)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	// Regex for Stable tag: 1.2.3
	re := regexp.MustCompile("(?i)Stable.tag:\\s?([\\w.]+)")
	matches := re.FindAllStringSubmatch(content, -1)
	if len(matches) > 0 && len(matches[0]) > 1 {
		return matches[0][1]
	}

	return ""
}

// IsVulnerable checks if detected version is within vulnerable range
// Simple comparison for now (e.g. "9.1.1" < "9.1.2")
func IsVulnerable(current, maxVulnerable string) bool {
	if current == "" { return true } // Assume vulnerable if version hidden
	return current <= maxVulnerable
}
