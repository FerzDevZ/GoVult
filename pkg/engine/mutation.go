package engine

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// MutatePayload generates various encoded versions for WAF bypass
func MutatePayload(p string) []string {
	var results []string
	results = append(results, p)

	// 1. URL Encoding
	u := url.QueryEscape(p)
	results = append(results, u)

	// 2. Double URL Encoding
	results = append(results, url.QueryEscape(u))

	// 3. Base64 Encoding
	b64 := base64.StdEncoding.EncodeToString([]byte(p))
	results = append(results, b64)

	// 4. HTML Entity (Hex)
	var hexStr string
	for _, r := range p {
		hexStr += fmt.Sprintf("&#x%x;", r)
	}
	results = append(results, hexStr)

	// 5. JavaScript CharCode
	var charCode string
	for i, r := range p {
		if i == 0 {
			charCode += fmt.Sprintf("String.fromCharCode(%d", r)
		} else {
			charCode += fmt.Sprintf(",%d", r)
		}
	}
	if charCode != "" {
		charCode += ")"
		results = append(results, charCode)
	}

	return results
}
