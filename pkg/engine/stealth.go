package engine

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// StealthTransport implements a custom RoundTripper that spoofs JA3 fingerprints
type StealthTransport struct {
	BaseTransport *http.Transport
	TargetBrowser string // "chrome", "firefox", "safari"
}

func NewStealthTransport(proxies []*ProxyRotator) *StealthTransport {
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	return &StealthTransport{
		BaseTransport: transport,
		TargetBrowser: "chrome",
	}
}

func (s *StealthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Synchronize User-Agent with the TLS Fingerprint
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	if s.TargetBrowser == "firefox" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
	}
	req.Header.Set("User-Agent", ua)

	// Ensure we handle DialTLS for JA3 spoofing
	s.BaseTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(network, addr, 10*time.Second)
		if err != nil {
			return nil, err
		}

		config := &utls.Config{
			ServerName: req.URL.Host,
		}

		// Spoofing Chrome 120
		uconn := utls.UClient(conn, config, utls.HelloChrome_Auto)
		if err := uconn.Handshake(); err != nil {
			return nil, err
		}

		return uconn, nil
	}

	return s.BaseTransport.RoundTrip(req)
}

// GetStealthClient returns a client with JA3 evasion capabilities
func GetStealthClient() *http.Client {
	return &http.Client{
		Transport: &StealthTransport{
			BaseTransport: &http.Transport{},
			TargetBrowser: "chrome",
		},
		Timeout: 30 * time.Second,
	}
}
