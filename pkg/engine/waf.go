package engine

import (
	"strings"
)

type WAFStatus struct {
	IsProtected bool
	Name        string
}

func DetectWAF(headers map[string][]string, statusCode int) WAFStatus {
	// Search for WAF Signatures in Headers
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		val := strings.ToLower(strings.Join(values, " "))

		// 1. Cloudflare
		if lowerKey == "cf-ray" || lowerKey == "cf-cache-status" || lowerKey == "server" && strings.Contains(val, "cloudflare") {
			return WAFStatus{IsProtected: true, Name: "Cloudflare"}
		}

		// 2. Hostinger CDN (HCDN) - User's target target uses this
		if lowerKey == "server" && strings.Contains(val, "hcdn") || lowerKey == "x-hcdn-request-id" {
			return WAFStatus{IsProtected: true, Name: "Hostinger CDN (HCDN)"}
		}

		// 3. LiteSpeed / Wordfence
		if lowerKey == "x-litespeed-cache" || lowerKey == "x-powered-by" && strings.Contains(val, "litespeed") {
			return WAFStatus{IsProtected: true, Name: "LiteSpeed / Wordfence"}
		}

		// 4. Sucuri
		if lowerKey == "x-sucuri-id" || lowerKey == "x-sucuri-cache" {
			return WAFStatus{IsProtected: true, Name: "Sucuri WebSite Firewall"}
		}
	}

	// Heuristics based on Status Code
	if statusCode == 403 || statusCode == 405 || statusCode == 406 {
		return WAFStatus{IsProtected: true, Name: "Generic WAF/Security Filter"}
	}

	return WAFStatus{IsProtected: false, Name: "None"}
}
