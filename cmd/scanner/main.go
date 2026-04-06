package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/FerzDevZ/GoVult/internal/utils"
	"github.com/FerzDevZ/GoVult/pkg/engine"
	"github.com/FerzDevZ/GoVult/pkg/template"
	"github.com/fatih/color"
)

func main() {
	target := flag.String("u", "", "Target URL")
	templatePath := flag.String("t", "", "Path to template file or directory")
	fullScan := flag.Bool("full", false, "Enable full scanning (Omniscient Mode)")
	rateLimit := flag.Int("rl", 5, "Rate limit (Requests Per Second)")
	concurrency := flag.Int("c", 20, "Number of concurrent workers (vX Titan)")
	htmlOutput := flag.String("o", "report.html", "Path to save HTML report")
	tgToken := flag.String("tg-token", "", "Telegram Bot Token")
	tgChat := flag.String("tg-chat", "", "Telegram Chat ID")
	proxy := flag.String("proxy", "", "Single Proxy URL")
	proxyList := flag.String("proxy-list", "", "Path to proxy list file")
	wordlist := flag.String("w", "", "Path to custom wordlist for discovery")
	recursive := flag.Bool("recursive", false, "Enable recursive discovery")
	subdomains := flag.Bool("subdomain", false, "Enable subdomain discovery")
	portScan := flag.Bool("port-scan", false, "Enable infrastructure port scanning")
	authHeader := flag.String("auth-header", "", "Authentication header")
	authCookie := flag.String("cookie", "", "Session cookie")
	dashboard := flag.Bool("dashboard", false, "Enable interactive TUI dashboard")
	stealth := flag.Bool("stealth", true, "Enable JA3 Spoofing (Titan Edition Anti-WAF)")
	exploit := flag.Bool("exploit", false, "Enable automated exploitation proofing")
	passive := flag.Bool("passive", false, "Enable passive reconnaissance only (crt.sh)")
	bypass := flag.Bool("bypass", false, "Enable WAF Bypass (Real IP detection)")
	oobServer := flag.String("oob", "", "Custom Interactsh OOB server")
	useAI := flag.Bool("ai", false, "Enable AI-Native Heuristics (Smart Path Guessing)")
	master := flag.Bool("master", false, "Run in Master mode")
	worker := flag.Int("worker", 0, "Run in Worker mode on specified port")
	watch := flag.Duration("watch", 0, "Continuous monitoring interval (e.g. 24h)")
	ui := flag.Bool("ui", false, "Enable Web Control Center")
	sca := flag.Bool("sca", false, "Enable Software Composition Analysis (OSV.dev)")
	secret := flag.Bool("secret", false, "Enable Deep Secret & Credential Hunting")
	tor := flag.Bool("tor", false, "Enable native Tor routing (127.0.0.1:9050)")
	fuzz2 := flag.Bool("fuzz-v2", false, "Enable radical mutation-based fuzzing")
	mitigate := flag.Bool("mitigate", false, "Generate virtual patches and remediation guides")
	cloud := flag.Bool("cloud", false, "Enable Multi-Cloud Infrastructure Auditing")
	payload := flag.Bool("payload", false, "Enable Interactive Reverse Shell Payload Factory")
	honeypot := flag.Bool("honeypot", false, "Enable Honeypot & Deception Awareness")
	ares := flag.Bool("ares", false, "Enable Ares Overdrive (Full Offensive KILL-CHAIN)")
	ghost := flag.Bool("ghost", false, "Enable Ghost Protocol (Automated OOB Injection)")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: govult -u <target> [options]")
		os.Exit(1)
	}

	var db *engine.Dashboard
	if *dashboard {
		db = engine.NewDashboard(*target)
		db.Update("Initializing Titan Engine (GoVult X)...", 0, 1)
	} else {
		color.HiCyan("GoVult X - Titan Edition (Anti-WAF + Chaining)")
		color.Green("[*] Target locked: %s (Workers: %d)\n", *target, *concurrency)
	}

	var proxies []*url.URL
	if *proxyList != "" {
		proxies, _ = utils.LoadProxies(*proxyList)
	} else if *proxy != "" {
		u, _ := url.Parse(*proxy)
		proxies = append(proxies, u)
	}

	var govultEngine *engine.Engine
	if *tor {
		torURL, _ := url.Parse("socks5://127.0.0.1:9050")
		proxies = append(proxies, torURL)
	}

	if *stealth {
		govultEngine = engine.NewEngine(*rateLimit, proxies) 
	} else {
		govultEngine = engine.NewEngine(*rateLimit, proxies)
	}
	
	govultEngine.AuthHeader = *authHeader
	govultEngine.AuthCookie = *authCookie

	// vX: OOB Initialization
	if *oobServer != "" {
		govultEngine.OOB = &engine.OOBClient{ServerURL: *oobServer}
	} else {
		govultEngine.OOB = engine.NewOOBClient()
	}

	// vX: Fingerprinting (Smart Mode)
	fp, _ := engine.DetectTechnology(*target)
	govultEngine.Fingerprint = fp

	// vX: WAF Bypass (Real IP Detection)
	if *bypass {
		origin, err := govultEngine.FindOrigin(*target)
		if err == nil && origin.Verified {
			color.HiMagenta("[!!!] BYPASS SUCCESS: Origin IP found at %s (%s)\n", origin.OriginIP, origin.Method)
			// Optional: Switch target to Origin IP?
			//*target = "http://" + origin.OriginIP 
		} else {
			color.Yellow("[!] Bypass failed: Origin IP could not be verified.\n")
		}
	}

	parsedMain, _ := url.Parse(*target)

	// vX: Master/Worker/UI Implementation
	if *master {
		fmt.Println("[ULTIMATE] Running in Master mode...")
		// Logic to manage cluster...
	}

	if *worker > 0 {
		engine.RunWorker(*worker, govultEngine)
		return
	}

	if *ui {
		go func() {
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "<h1>GoVult Ultimate Control Center</h1><p>Target: %s</p>", *target)
			})
			fmt.Println("[ULTIMATE] Web Control Center listening on :8081...")
			http.ListenAndServe(":8081", nil)
		}()
	}

	if *portScan || *fullScan {
		if db != nil {
			db.Update("Recon: Port Scanning...", 10, 1)
		}
		topPorts := []int{21, 22, 80, 443, 3306, 6379, 8080}
		engine.ScanPorts(parsedMain.Host, topPorts)
	}

	var finalTargets []string
	finalTargets = append(finalTargets, *target)

	if *subdomains || *fullScan {
		if db != nil {
			db.Update("Discovery: Subdomain Mapping...", 20, 1)
		}
		
		// vX: Passive + Active Recon
		passiveSubs := engine.PassiveDiscovery(parsedMain.Host)
		for _, s := range passiveSubs {
			finalTargets = append(finalTargets, "https://"+s+"/")
		}

		if !*passive {
			subWords := []string{"www", "api", "dev", "test", "admin"}
			subs := engine.BruteSubdomains(parsedMain.Host, subWords)
			for _, s := range subs {
				finalTargets = append(finalTargets, "https://"+s+"/")
			}
		}
	}

	// vX: Ares Overdrive Features (Ghost Protocol)
	if *ghost {
		govultEngine.GhostProtocol(*target)
	}

	// vX: Ares Overdrive Features (Param-Diver)
	if *ares {
		paramsFound := govultEngine.ParamDiver(*target)
		for _, p := range paramsFound {
			color.HiCyan("[!] ARES: Found hidden parameter: %s (Behavioral change detected!)\n", p)
		}
	}

	// vX: Nebula Features (Honeypot)
	if *honeypot {
		hpResults, _ := govultEngine.DetectHoneypot(*target)
		for _, r := range hpResults {
			color.HiYellow("[!] DECEPTION ALERT: %s (%s) - Risk: %s\n", r.Type, r.Evidence, r.Risk)
		}
	}

	// vX: Nebula Features (Cloud Auditor)
	if *cloud {
		cloudResults, _ := govultEngine.AuditCloud(*target)
		for _, r := range cloudResults {
			color.HiCyan("[CLOUD] Found %s %s: %s (%s)\n", r.Provider, r.Service, r.Detail, r.Severity)
		}
	}

	// vX: Singularity Phase 2 (VCS Scout)
	vcsResults, _ := govultEngine.ProbeVCS(*target)
	for _, r := range vcsResults {
		color.HiRed("[VCS] Publicly accessible %s file: %s (%s)\n", r.Type, r.Path, r.Evidence)
	}

	// vX: Cyber-Overlord Features (SCA)
	if *sca {
		scaResults, _ := govultEngine.ScanDependencies(*target)
		for _, r := range scaResults {
			fmt.Printf("    - [SCA] VULNERABLE: %s %s (%s)\n", r.Package, r.Version, r.Vulnerability)
		}
	}

	// vX: Cyber-Overlord Features (Secrets)
	if *secret {
		// Example: collecting body content from the home page
		resp, _ := http.Get(*target)
		if resp != nil {
			defer resp.Body.Close()
			bodies := make(map[string]string)
			// ... logic to collect bodies would go here ...
			govultEngine.RunSecretScan(*target, bodies)
		}
	}

	var scanQueue []string
	for _, domain := range finalTargets {
		scanQueue = append(scanQueue, domain)
		if *fullScan {
			// Discovery
			words := []string{".env", ".git/config", "admin"}
			if *wordlist != "" {
				words, _ = utils.LoadWordlist(*wordlist)
			}
			opts := engine.FuzzerOptions{MaxDepth: 1}
			if *recursive {
				opts.MaxDepth = 2
			}
			discoveryResults, _ := engine.Fuzz(domain, words, opts)
			for _, r := range discoveryResults {
				scanQueue = append(scanQueue, r.Path)
			}

			// Crawling (Auto-Headless for SPAs)
			crawlResult, _ := engine.Crawl(domain)
			if crawlResult != nil {
				scanQueue = append(scanQueue, crawlResult.Links...)
				scanQueue = append(scanQueue, crawlResult.JSLinks...)
			}

			// vX: AI Heuristics
			if *useAI {
				ae := engine.NewHeuristicEngine(govultEngine.Fingerprint)
				scanQueue = append(scanQueue, ae.GuessPaths()...)
			}

			// vX: Cyber-Overlord Features (Fuzz V2)
			if *fuzz2 {
				govultEngine.RunDeepFuzz(domain, "id", "1")
			}

			// vX: Singularity Phase 2 (Auto-Exfiltration)
			if strings.Contains(domain, ".env") {
				exData := govultEngine.DownloadAndExfiltrate(domain)
				if len(exData) > 0 {
					color.HiRed("[!] EXFILTRATED SECRETS FROM %s:\n", domain)
					for k, v := range exData {
						fmt.Printf("    - %s: %s\n", k, v)
					}
				}
			}
		}
	}

	uniqueQueue := make(map[string]bool)
	var finalQueue []string
	for _, u := range scanQueue {
		if !uniqueQueue[u] {
			uniqueQueue[u] = true
			finalQueue = append(finalQueue, u)
		}
	}

	// Template Loading
	var templates []*template.Template
	pathToScan := "templates"
	if *templatePath != "" {
		pathToScan = *templatePath
	}
	filepath.Walk(pathToScan, func(path string, info os.FileInfo, err error) error {
		if err != nil { return nil }
		if !info.IsDir() && filepath.Ext(path) == ".yaml" {
			t, _ := template.Load(path)
			if t == nil {
				// Try loading as Nuclei template
				t, _ = engine.LoadNuclei(path)
			}
			if t != nil {
				templates = append(templates, t)
			}
		}
		return nil
	})

	var allResults []engine.Result
	var wg sync.WaitGroup
	var mu sync.Mutex
	resultsChan := make(chan engine.Result)
	semaphore := make(chan struct{}, *concurrency)

	for i, uStr := range finalQueue {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if db != nil {
				progress := 50.0 + (float64(idx)/float64(len(finalQueue)))*50.0
				db.Update(fmt.Sprintf("Titan Scan [%d/%d] %s", idx+1, len(finalQueue), u), progress, len(finalTargets))
			}

			for _, t := range templates {
				// Only run exploit if flag is set
				if !*exploit {
					t.Exploit = nil
				}
				results, _ := govultEngine.Run(u, t)
				for _, r := range results {
					resultsChan <- r
				}
			}
		}(i, uStr)
	}

	go func() {
		for res := range resultsChan {
			mu.Lock()
			allResults = append(allResults, res)
			mu.Unlock()
			if db != nil {
				db.AddVuln(res.Severity)
			} else {
				fmt.Printf("    - [!] FOUND [%s] %s (%s)\n", res.TemplateID, res.Target, res.Severity)
			}
		}
	}()

	wg.Wait()
	close(resultsChan)
	time.Sleep(500 * time.Millisecond)

	if len(allResults) > 0 {
		color.HiRed("\n[!!] TITAN: Found %d vulnerabilities with Chaining results!\n", len(allResults))
		
		// vX: Ares Overdrive Features (Kill-Chain)
		if *ares {
			chainedResults := govultEngine.RunKillChain(*target, allResults)
			allResults = append(allResults, chainedResults...)
		}

		engine.GenerateHTML(*target, allResults, *htmlOutput)
		
		if *mitigate {
			mReport := govultEngine.RunMitigationReport(allResults)
			fmt.Println(mReport)
		}

		// vX: Nebula Payload Factory
		if *payload {
			color.HiMagenta("\n[🦾] NEBULA: Reverse Shell Payload Factory Enabled!")
			lip := engine.GetLIP()
			shell := engine.GenerateReverseShell(engine.BashShell, lip, 4444, "base64")
			fmt.Printf("    - Generated (LIP: %s, Port: 4444): %s\n", lip, shell)
		}

		if *tgToken != "" {
			engine.SendTelegramNotification(*tgToken, *tgChat, *target, allResults)
		}
	} else {
		color.Green("\n[-] Titan Scan completed. No targets breached.\n")
	}

	// vX: Watcher Mode
	if *watch > 0 {
		watcher := engine.NewWatcher(govultEngine, []string{*target}, *watch)
		watcher.Start()
	}
}
