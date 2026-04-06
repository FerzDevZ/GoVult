package engine

import (
	"fmt"
	"net/http"
)

// CloudResult represents findings from cloud auditing
type CloudResult struct {
	Provider string
	Service  string
	Severity string
	Detail   string
}

// AuditCloud probes for cloud-specific misconfigurations
func (e *Engine) AuditCloud(target string) ([]CloudResult, error) {
	var results []CloudResult
	fmt.Printf("[CLOUD] Identifying provider and auditing infrastructure...\n")

	// 1. AWS Metadata Probe (IMDSv1 vs IMDSv2)
	awsRes, _ := e.probeAWSMetadata()
	if awsRes != nil {
		results = append(results, *awsRes)
	}

	// 2. GCP Metadata Probe
	gcpRes, _ := e.probeGCPMetadata()
	if gcpRes != nil {
		results = append(results, *gcpRes)
	}

	// 3. Azure Metadata Probe
	azureRes, _ := e.probeAzureMetadata()
	if azureRes != nil {
		results = append(results, *azureRes)
	}

	return results, nil
}

func (e *Engine) probeAWSMetadata() (*CloudResult, error) {
	// Probing IMDSv1 (Legacy/Vulnerable)
	u := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	resp, err := e.Client.Get(u)
	if err == nil && resp.StatusCode == 200 {
		return &CloudResult{
			Provider: "AWS",
			Service:  "EC2 Metadata",
			Severity: "Critical",
			Detail:   "IMDSv1 is enabled. Vulnerable to SSRF exfiltration.",
		}, nil
	}
	return nil, nil
}

func (e *Engine) probeGCPMetadata() (*CloudResult, error) {
	u := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := e.Client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		return &CloudResult{
			Provider: "GCP",
			Service:  "Compute Metadata",
			Severity: "High",
			Detail:   "Vulnerable to Header-authenticated SSRF.",
		}, nil
	}
	return nil, nil
}

func (e *Engine) probeAzureMetadata() (*CloudResult, error) {
	u := "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Metadata", "true")
	resp, err := e.Client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		return &CloudResult{
			Provider: "Azure",
			Service:  "Instance Metadata",
			Severity: "High",
			Detail:   "Vulnerable to Header-authenticated SSRF.",
		}, nil
	}
	return nil, nil
}

func (e *Engine) ScanBuckets(domain string) []string {
	// Logic to scan for {domain}-backup.s3.amazonaws.com, etc.
	return nil
}
