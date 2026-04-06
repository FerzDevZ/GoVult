package engine

import (
	"fmt"
)

// VCSResult represents findings for version control leaks
type VCSResult struct {
	Type     string // "Git", "SVN"
	Path     string
	Evidence string
}

// ProbeVCS performs deep child-probing for version control metadata
func (e *Engine) ProbeVCS(target string) ([]VCSResult, error) {
	fmt.Printf("[VCS] Probing for deep version control leaks (Git/SVN)...\n")
	var results []VCSResult

	gitPaths := []string{"/.git/index", "/.git/config", "/.git/HEAD", "/.git/refs/heads/master"}
	for _, p := range gitPaths {
		u := target + p
		resp, err := e.Client.Get(u)
		if err == nil && resp.StatusCode == 200 {
			fmt.Printf("    [!] Found Git metadata: %s\n", p)
			results = append(results, VCSResult{
				Type:     "Git",
				Path:     p,
				Evidence: fmt.Sprintf("File %s is publicly accessible.", p),
			})
		}
	}

	svnPaths := []string{"/.svn/entries", "/.svn/wc.db", "/.svn/all-wcprops"}
	for _, p := range svnPaths {
		u := target + p
		resp, err := e.Client.Get(u)
		if err == nil && resp.StatusCode == 200 {
			fmt.Printf("    [!] Found SVN metadata: %s\n", p)
			results = append(results, VCSResult{
				Type:     "SVN",
				Path:     p,
				Evidence: fmt.Sprintf("File %s is publicly accessible.", p),
			})
		}
	}

	return results, nil
}
