package engine

import (
	"fmt"
	"math"
	"regexp"
)

// SecretType represents detected credential types
type SecretType string

const (
	AWSSecret      SecretType = "AWS Access Key"
	StripeSecret   SecretType = "Stripe API Key"
	GoogleSecret   SecretType = "Google API Key"
	GenericSecret  SecretType = "High-Entropy Secret"
)

// SecretResult stores findings from secret scanning
type SecretResult struct {
	Type     SecretType
	Value    string
	Entropy  float64
	File     string
}

// SearchSecrets scans a string (JS/ENV content) for potential credentials
func SearchSecrets(content, source string) []SecretResult {
	var results []SecretResult

	patterns := map[SecretType]*regexp.Regexp{
		AWSSecret:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		StripeSecret: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		GoogleSecret: regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
	}

	for sType, re := range patterns {
		matches := re.FindAllString(content, -1)
		for _, m := range matches {
			results = append(results, SecretResult{
				Type:     sType,
				Value:    m,
				Entropy:  calculateEntropy(m),
				File:     source,
			})
		}
	}

	// High-Entropy Detection (Generic)
	// Scan for long random strings (e.g. 32+ chars)
	reGeneric := regexp.MustCompile(`[a-zA-Z0-9+/=]{32,}`)
	matches := reGeneric.FindAllString(content, -1)
	for _, m := range matches {
		entropy := calculateEntropy(m)
		if entropy > 4.5 { // Threshold for potential secrets
			results = append(results, SecretResult{
				Type:     GenericSecret,
				Value:    m,
				Entropy:  entropy,
				File:     source,
			})
		}
	}

	return results
}

// calculateEntropy computes the Shannon entropy of a string
func calculateEntropy(s string) float64 {
	m := make(map[rune]float64)
	for _, r := range s {
		m[r]++
	}
	var entropy float64
	for _, v := range m {
		p := v / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func (e *Engine) RunSecretScan(target string, bodies map[string]string) []SecretResult {
	fmt.Printf("[SECRETS] Hunting for credentials and high-entropy keys across %d files...\n", len(bodies))
	var allResults []SecretResult
	for file, content := range bodies {
		results := SearchSecrets(content, file)
		allResults = append(allResults, results...)
	}
	return allResults
}
