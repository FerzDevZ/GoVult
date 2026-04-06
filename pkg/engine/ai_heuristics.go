package engine

import (
	"fmt"
	"strings"
)

// HeuristicEngine manages smart path and parameter guessing
type HeuristicEngine struct {
	Fingerprint *Fingerprint
}

func NewHeuristicEngine(fp *Fingerprint) *HeuristicEngine {
	return &HeuristicEngine{Fingerprint: fp}
}

// GuessPaths generates potential sensitive paths based on target technology
func (h *HeuristicEngine) GuessPaths() []string {
	var paths []string
	if h.Fingerprint == nil {
		return []string{".env", ".git/config", "admin"}
	}

	fmt.Printf("[AI-HEURISTICS] Generating smart paths for: %s (CMS: %s, Framework: %s)\n", 
		h.Fingerprint.Server, h.Fingerprint.CMS, h.Fingerprint.Framework)

	// Framework-specific paths
	if h.Fingerprint.CMS == "WordPress" {
		paths = append(paths, "wp-config.php.bak", "wp-content/debug.log", "wp-json/wp/v2/users")
	}
	if strings.Contains(h.Fingerprint.Framework, "Next.js") {
		paths = append(paths, ".next/BUILD_ID", "api/hello", "_next/static/chunks/main.js")
	}
	if strings.Contains(h.Fingerprint.Framework, "PHP") {
		paths = append(paths, "info.php", "config.php.swp", "composer.json")
	}

	// Generic high-value paths
	paths = append(paths, ".env", ".aws/credentials", ".docker/config.json")

	return paths
}

// GuessParams generates potential sensitive parameters
func (h *HeuristicEngine) GuessParams() []string {
	return []string{"debug", "admin", "test", "dev", "internal", "access_token"}
}
