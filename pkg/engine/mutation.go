package engine

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// MutatePayload generates basic encoded versions for WAF bypass
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

// MutateAdvanced performs polymorphic mutation for WAF bypass
func MutateAdvanced(p string) []string {
	var results []string
	results = append(results, MutatePayload(p)...)

	// 1. SQL Comment Injection (SEL/**/ECT)
	if strings.Contains(strings.ToUpper(p), "SELECT") {
		results = append(results, strings.Replace(p, "SELECT", "SEL/**/ECT", -1))
		results = append(results, strings.Replace(p, "SELECT", "SEL/*%00*/ECT", -1))
	}

	// 2. Case Switching (<sCrIpT>)
	var cased string
	for i, r := range p {
		if i%2 == 0 {
			cased += strings.ToUpper(string(r))
		} else {
			cased += strings.ToLower(string(r))
		}
	}
	results = append(results, cased)

	// 3. Null Byte Injection
	results = append(results, p+"%00")
	results = append(results, p+"\x00")

	// 4. Unicode Bypass
	results = append(results, strings.Replace(p, "'", "％27", -1)) // Full-width apostrophe

	return results
}
