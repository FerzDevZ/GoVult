package engine

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// StealthTransport implements a custom RoundTripper that spoofs JA3 fingerprints
type StealthTransport struct {
	BaseTransport *http.Transport
	TargetBrowser string // "chrome", "firefox", "safari"
	ProxyURL      *url.URL
}

func NewStealthTransport(proxyURL *url.URL) *StealthTransport {
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true, // vX Titan: Enable HTTP/2
	}

	if proxyURL != nil {
		if proxyURL.Scheme == "socks5" {
			dialer, _ := proxy.SOCKS5("tcp", proxyURL.Host, nil, proxy.Direct)
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &StealthTransport{
		BaseTransport: transport,
		TargetBrowser: "chrome",
		ProxyURL:      proxyURL,
	}
}

func (s *StealthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Sync UA with TLS Fingerprint
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	spec := utls.HelloChrome_Auto

	if s.TargetBrowser == "firefox" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
		spec = utls.HelloFirefox_Auto
	}
	req.Header.Set("User-Agent", ua)

	s.BaseTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(network, addr, 10*time.Second)
		if err != nil {
			return nil, err
		}

		config := &utls.Config{ServerName: req.URL.Host}
		uconn := utls.UClient(conn, config, spec)
		if err := uconn.Handshake(); err != nil {
			return nil, err
		}

		return uconn, nil
	}

	return s.BaseTransport.RoundTrip(req)
}

func GetStealthClient(proxyURL *url.URL) *http.Client {
	return &http.Client{
		Transport: NewStealthTransport(proxyURL),
		Timeout:   30 * time.Second,
	}
}
