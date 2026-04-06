package engine

import (
	"fmt"
	"time"
)

// OOBClient handles Interactsh communications
type OOBClient struct {
	ServerURL string
	Token     string
	Subdomain string
}

type InteractshRegisterResponse struct {
	CorrelationID string `json:"correlation_id"`
	SecretKey     string `json:"secret_key"`
}

func NewOOBClient() *OOBClient {
	return &OOBClient{
		ServerURL: "interactsh.com", // Default public server
	}
}

// GenerateURL creates a new OOB tracking URL
func (c *OOBClient) GenerateURL() (string, string) {
	// Simple identifier for demo. In reality, requires registration via library.
	id := fmt.Sprintf("titan-%d.interactsh.com", time.Now().UnixNano())
	return id, id
}

// Poll checks for incoming interactions for the given ID
func (c *OOBClient) Poll(correlationID string) (bool, string) {
	fmt.Printf("[OOB] Polling for interactions for %s...\n", correlationID)
	// Simplified polling logic for demonstration
	// Real implementation would use the Interactsh API (JSON)
	return false, "No interactions yet."
}

// OOBResult stores OOB interaction data
type OOBResult struct {
	Interacted bool
	Protocol   string // DNS, HTTP, SMTP
	Timestamp  string
	IP         string
}
