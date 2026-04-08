package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

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
	jsonOutput := flag.String("json-out", "", "Path to save JSON report")
	sarifOutput := flag.String("sarif-out", "", "Path to save SARIF report")
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
	turbo := flag.Bool("turbo", false, "Enable Turbo Mode (High Speed + Parallel Recon)")
	depth := flag.Int("depth", 2, "Maximum crawling depth")
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

<<<<<<< HEAD
	if *turbo {
		govultEngine.Turbo = true
		if *rateLimit == 5 { *rateLimit = 50 }
		if *concurrency == 20 { *concurrency = 100 }
		*useAI = true
		color.HiYellow("[TURBO] Mode Enabled: RPS=%d, Workers=%d, Jitter=OFF", *rateLimit, *concurrency)
	}
	
=======
>>>>>>> 8aaf884 (new update)
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

	// vX: Parallel Recon Pipeline
	var reconWG sync.WaitGroup

	if *portScan || *fullScan {
		reconWG.Add(1)
		go func() {
			defer reconWG.Done()
			if db != nil {
				db.Update("Recon: Port Scanning...", 10, 1)
			}
			topPorts := []int{21, 22, 80, 443, 3306, 6379, 8080}
			engine.ScanPorts(parsedMain.Host, topPorts)
		}()
	}

	var finalTargets []string
	finalTargets = append(finalTargets, *target)
	var targetsMu sync.Mutex

	if *subdomains || *fullScan {
<<<<<<< HEAD
		reconWG.Add(1)
		go func() {
			defer reconWG.Done()
			if db != nil {
				db.Update("Discovery: Subdomain Mapping...", 20, 1)
			}
			
			// vX: Passive + Active Recon
			passiveSubs := engine.PassiveDiscovery(parsedMain.Host)
			targetsMu.Lock()
			for _, s := range passiveSubs {
=======
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
>>>>>>> 8aaf884 (new update)
				finalTargets = append(finalTargets, "https://"+s+"/")
			}
			targetsMu.Unlock()

			if !*passive {
				subWords := []string{"www", "api", "dev", "test", "admin"}
				subs := engine.BruteSubdomains(parsedMain.Host, subWords)
				targetsMu.Lock()
				for _, s := range subs {
					finalTargets = append(finalTargets, "https://"+s+"/")
				}
				targetsMu.Unlock()
			}
		}()
	}

	// vX: Ares Overdrive Features (Ghost Protocol)
	if *ghost {
		reconWG.Add(1)
		go func() {
			defer reconWG.Done()
			govultEngine.GhostProtocol(*target)
		}()
	}

	// vX: Ares Overdrive Features (Param-Diver)
	if *ares {
		reconWG.Add(1)
		go func() {
			defer reconWG.Done()
			paramsFound := govultEngine.ParamDiver(*target)
			for _, p := range paramsFound {
				color.HiCyan("[!] ARES: Found hidden parameter: %s (Behavioral change detected!)\n", p)
			}
		}()
	}

	// vX: Nebula Features (Honeypot)
	if *honeypot {
		reconWG.Add(1)
		go func() {
			defer reconWG.Done()
			hpResults, _ := govultEngine.DetectHoneypot(*target)
			for _, r := range hpResults {
				color.HiYellow("[!] DECEPTION ALERT: %s (%s) - Risk: %s\n", r.Type, r.Evidence, r.Risk)
			}
		}()
	}

	// vX: Nebula Features (Cloud Auditor)
	if *cloud {
		reconWG.Add(1)
		go func() {
			defer reconWG.Done()
			cloudResults, _ := govultEngine.AuditCloud(*target)
			for _, r := range cloudResults {
				color.HiCyan("[CLOUD] Found %s %s: %s (%s)\n", r.Provider, r.Service, r.Detail, r.Severity)
			}
		}()
	}

	// vX: Singularity Phase 2 (VCS Scout)
	reconWG.Add(1)
	go func() {
		defer reconWG.Done()
		vcsResults, _ := govultEngine.ProbeVCS(*target)
		for _, r := range vcsResults {
			color.HiRed("[VCS] Publicly accessible %s file: %s (%s)\n", r.Type, r.Path, r.Evidence)
		}
	}()

	// Wait for Recon Phase 1 to complete if not in Turbo, or just continue
	if !*turbo {
		reconWG.Wait()
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
		resp, _ := govultEngine.Client.Get(*target)
		if resp != nil {
			defer resp.Body.Close()
			bodies := make(map[string]string)
			// ... logic to collect bodies would go here ...
			govultEngine.RunSecretScan(*target, bodies)
		}
	}

	// Build Scan Queue
	var scanQueue []string
	uniqueQueue := make(map[string]bool)

	// 1. Initial Targets (Subdomains + Main)
	for _, domain := range finalTargets {
		if !uniqueQueue[domain] {
			uniqueQueue[domain] = true
			scanQueue = append(scanQueue, domain)
		}
	}

	// 2. Deep Discovery & Crawling (Only on primary target to avoid exploding requests)
	if *fullScan {
		color.HiYellow("[SYSTEM] Running deep discovery and crawl on primary target: %s\n", *target)

		// Discovery
		words := []string{".env", ".git/config", "admin", "config", "backup"}
		if *wordlist != "" {
			words, _ = utils.LoadWordlist(*wordlist)
		}
		fuzzOpts := engine.FuzzerOptions{MaxDepth: 1}
		if *recursive {
			fuzzOpts.MaxDepth = 2
		}
		discoveryResults, _ := engine.Fuzz(*target, words, fuzzOpts)
		for _, r := range discoveryResults {
			if !uniqueQueue[r.Path] {
				uniqueQueue[r.Path] = true
				scanQueue = append(scanQueue, r.Path)
			}
		}

		// Crawling
		crawlResult, _ := engine.Crawl(*target, *depth)
		if crawlResult != nil {
			for _, l := range append(crawlResult.Links, crawlResult.JSLinks...) {
				if !uniqueQueue[l] {
					uniqueQueue[l] = true
					scanQueue = append(scanQueue, l)
				}
			}
		}

		// vX: Cyber-Overlord Features (Fuzz V2)
		if *fuzz2 {
			govultEngine.RunDeepFuzz(*target, "id", "1")
		}

		// vX: AI Heuristics
		if *useAI {
			ae := engine.NewHeuristicEngine(govultEngine.Fingerprint)
			for _, p := range ae.GuessPaths() {
				if !uniqueQueue[*target+p] {
					uniqueQueue[*target+p] = true
					scanQueue = append(scanQueue, *target+p)
				}
			}
		}
	}

	finalQueue := scanQueue

	// Template Loading
	var templates []*template.Template
	pathToScan := "templates"
	if *templatePath != "" {
		pathToScan = *templatePath
	}
	filepath.Walk(pathToScan, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
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
	var collectorWG sync.WaitGroup
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
				// Clone template to avoid shared mutation across goroutines.
				templateCopy := *t
				if !*exploit {
					templateCopy.Exploit = nil
				}
				results, _ := govultEngine.Run(u, &templateCopy)
				for _, r := range results {
					resultsChan <- r
				}
			}
		}(i, uStr)
	}

	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
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
	collectorWG.Wait()

	if len(allResults) > 0 {
		color.HiRed("\n[!!] TITAN: Found %d vulnerabilities with Chaining results!\n", len(allResults))

		// vX: Ares Overdrive Features (Kill-Chain)
		if *ares {
			chainedResults := govultEngine.RunKillChain(*target, allResults)
			allResults = append(allResults, chainedResults...)
		}

		engine.GenerateHTML(*target, allResults, *htmlOutput)
		if *jsonOutput != "" {
			engine.GenerateJSON(*target, allResults, *jsonOutput)
		}
		if *sarifOutput != "" {
			engine.GenerateSARIF(allResults, *sarifOutput)
		}

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
