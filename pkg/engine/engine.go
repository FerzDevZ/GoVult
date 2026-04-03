package engine

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/FerzDevZ/GoVult/pkg/template"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

type Result struct {
	TemplateID  string
	Target      string
	Severity    string
	Matched     bool
	Description string
	Remediation string
	CVSS        float64
}

type ProxyRotator struct {
	Proxies []*url.URL
	Index   int
	Mu      sync.Mutex
}

func (pr *ProxyRotator) Next() *url.URL {
	pr.Mu.Lock()
	defer pr.Mu.Unlock()
	if len(pr.Proxies) == 0 {
		return nil
	}
	u := pr.Proxies[pr.Index]
	pr.Index = (pr.Index + 1) % len(pr.Proxies)
	return u
}

type Engine struct {
	Client      *http.Client
	Limiter     *rate.Limiter
	Rotator     *ProxyRotator
	AuthHeader  string
	AuthCookie  string
}

func NewEngine(rps int, proxies []*url.URL) *Engine {
	rotator := &ProxyRotator{Proxies: proxies}
	jar, _ := cookiejar.New(nil)
	
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if len(proxies) > 0 {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			pURL := rotator.Next()
			if pURL != nil && (pURL.Scheme == "socks5" || pURL.Scheme == "socks4") {
				dialer, err := proxy.FromURL(pURL, proxy.Direct)
				if err == nil {
					return dialer.Dial(network, addr)
				}
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return rotator.Next(), nil
		}
	}

	return &Engine{
		Client: &http.Client{
			Timeout:   20 * time.Second,
			Transport: transport,
			Jar:       jar,
		},
		Limiter: rate.NewLimiter(rate.Limit(rps), 1),
		Rotator: rotator,
	}
}

func (e *Engine) Run(target string, t *template.Template) ([]Result, error) {
	var results []Result
	var fastReqs []template.Request
	var deepReqs []template.Request

	for _, req := range t.Requests {
		isDeep := false
		for _, m := range req.Matchers {
			if m.Type == "time" || strings.Contains(m.Part, "time") {
				isDeep = true
			}
		}
		if isDeep {
			deepReqs = append(deepReqs, req)
		} else {
			fastReqs = append(fastReqs, req)
		}
	}

	for _, req := range fastReqs {
		for _, path := range req.Path {
			e.Limiter.Wait(context.Background())
			u := target + path
			res, _ := e.scanSingle(u, req.Method, req.Matchers, t)
			if res != nil {
				res.Description = t.Info.Description
				res.Remediation = GetRemediation(t.ID)
				res.CVSS = GetCVSS(t.Info.Severity)
				results = append(results, *res)
			}
		}
	}

	for _, req := range deepReqs {
		for _, path := range req.Path {
			e.Limiter.Wait(context.Background())
			u := target + path
			res, _ := e.scanSingle(u, req.Method, req.Matchers, t)
			if res != nil {
				res.Description = t.Info.Description
				res.Remediation = GetRemediation(t.ID)
				res.CVSS = GetCVSS(t.Info.Severity)
				results = append(results, *res)
			}
		}
	}

	parsed, err := url.Parse(target)
	if err == nil && parsed.RawQuery != "" {
		injectResults, _ := e.ScanParams(target, t)
		for i := range injectResults {
			injectResults[i].Description = t.Info.Description
			injectResults[i].Remediation = GetRemediation(t.ID)
			injectResults[i].CVSS = GetCVSS(t.Info.Severity)
		}
		results = append(results, injectResults...)
	}

	return results, nil
}

func (e *Engine) scanSingle(u, method string, matchers []template.Matcher, t *template.Template) (*Result, error) {
	httpReq, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, err
	}

	// v6.0: WAF Bypass Headers (Intelligent Spoofing)
	httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")
	httpReq.Header.Set("X-Real-IP", "127.0.0.1")
	httpReq.Header.Set("X-Originating-IP", "127.0.0.1")
	httpReq.Header.Set("CF-Connecting-IP", "127.0.0.1")
	httpReq.Header.Set("True-Client-IP", "127.0.0.1")

	if e.AuthHeader != "" {
		parts := strings.SplitN(e.AuthHeader, ":", 2)
		if len(parts) == 2 {
			httpReq.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if e.AuthCookie != "" {
		httpReq.Header.Set("Cookie", e.AuthCookie)
	}

	start := time.Now()
	resp, err := e.Client.Do(httpReq)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	
	if Match(string(body), resp.StatusCode, matchers) {
		return &Result{
			TemplateID: t.ID,
			Target:     u,
			Severity:   t.Info.Severity,
			Matched:    true,
		}, nil
	}

	if strings.Contains(t.ID, "sqli") && duration >= 5*time.Second {
		return &Result{
			TemplateID: t.ID + "-blind",
			Target:     u,
			Severity:   "critical",
			Matched:    true,
		}, nil
	}

	return nil, nil
}

// GetCVSS returns industry-standard severity scoring
func GetCVSS(severity string) float64 {
	switch severity {
	case "critical": return 9.8
	case "high":     return 8.5
	case "medium":   return 5.5
	case "low":      return 2.5
	default:         return 0.0
	}
}

// GetRemediation provides actionable fix advice for stakeholders
func GetRemediation(id string) string {
	if strings.Contains(id, "sqli") {
		return "Use Prepared Statements/Parameterized Queries and ensure DB user has least privilege."
	}
	if strings.Contains(id, "xss") {
		return "Implement Context-Aware Output Encoding and enforce Content Security Policy (CSP)."
	}
	if strings.Contains(id, "rce") {
		return "Disable dangerous PHP functions (system, exec) and strictly validate system-level inputs."
	}
	if strings.Contains(id, "disclosure") || strings.Contains(id, "secret") {
		return "Restrict access via .htaccess/nginx conf and move sensitive files outside document root."
	}
	if strings.Contains(id, "cve-2024-10924") {
		return "Update 'Really Simple Security' plugin to version 9.1.2 or higher IMMEDIATELY."
	}
	return "Update affected component to the latest version and restrict public access."
}

func (e *Engine) ScanParams(target string, t *template.Template) ([]Result, error) {
	var results []Result
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	queryParams := u.Query()
	for key := range queryParams {
		for _, req := range t.Requests {
			payloads := MutatePayload("1' AND SLEEP(5)--") 
			for _, payload := range payloads {
				e.Limiter.Wait(context.Background())
				
				testParams := u.Query()
				testParams.Set(key, payload)
				u.RawQuery = testParams.Encode()
				testURL := u.String()

				res, _ := e.scanSingle(testURL, "GET", req.Matchers, t)
				if res != nil {
					results = append(results, *res)
					break
				}
			}
		}
	}
	return results, nil
}
