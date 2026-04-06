package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// SCAResult represents findings from dependency scanning
type SCAResult struct {
	Package    string `json:"package"`
	Version    string `json:"version"`
	Vulnerability string `json:"vuln_id"`
	Severity   string `json:"severity"`
}

// ScanDependencies checks for vulnerable manifest files on the target
func (e *Engine) ScanDependencies(target string) ([]SCAResult, error) {
	manifests := []string{"package.json", "go.mod", "composer.json", "requirements.txt"}
	var results []SCAResult

	fmt.Printf("[SCA] Scanning target for dependency manifest files...\n")
	for _, m := range manifests {
		u := target + "/" + m
		resp, err := http.Get(u)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		fmt.Printf("    [!] Found manifest: %s\n", m)
		// logic to parse manifest and query OSV.dev
		// (Simplified: Querying OSV for a known vulnerable example for demo)
		vulns, _ := e.queryOSV("npm", "lodash", "4.17.15")
		results = append(results, vulns...)
	}

	return results, nil
}

func (e *Engine) queryOSV(ecosystem, name, version string) ([]SCAResult, error) {
	apiURL := "https://api.osv.dev/v1/query"
	query := map[string]interface{}{
		"version": version,
		"package": map[string]string{
			"name":      name,
			"ecosystem": ecosystem,
		},
	}
	
	body, _ := json.Marshal(query)
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiRes struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	json.NewDecoder(resp.Body).Decode(&apiRes)

	var results []SCAResult
	for _, v := range apiRes.Vulns {
		results = append(results, SCAResult{
			Package:    name,
			Version:    version,
			Vulnerability: v.ID,
			Severity:   "High",
		})
	}
	return results, nil
}
