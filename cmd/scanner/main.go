package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
	concurrency := flag.Int("c", 20, "Number of concurrent workers (v5.1 Turbo)")
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
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: govult -u <target> [options]")
		os.Exit(1)
	}

	var db *engine.Dashboard
	if *dashboard {
		db = engine.NewDashboard(*target)
		db.Update("Initializing Turbo Engine...", 0, 1)
	} else {
		color.HiCyan("GoVult v5.1 - Turbo & CVE Edition")
		color.Green("[*] Target locked: %s (Workers: %d)\n", *target, *concurrency)
	}

	var proxies []*url.URL
	if *proxyList != "" {
		proxies, _ = utils.LoadProxies(*proxyList)
	} else if *proxy != "" {
		u, _ := url.Parse(*proxy)
		proxies = append(proxies, u)
	}
	govultEngine := engine.NewEngine(*rateLimit, proxies)
	govultEngine.AuthHeader = *authHeader
	govultEngine.AuthCookie = *authCookie

	parsedMain, _ := url.Parse(*target)
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
		subWords := []string{"www", "api", "dev", "test", "admin"}
		subs := engine.BruteSubdomains(parsedMain.Host, subWords)
		for _, s := range subs {
			finalTargets = append(finalTargets, "https://"+s+"/")
		}
	}

	var scanQueue []string
	for _, domain := range finalTargets {
		scanQueue = append(scanQueue, domain)
		if *fullScan {
			// Discovery with recursive support
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

			// Crawling
			crawlResult, _ := engine.Crawl(domain)
			if crawlResult != nil {
				scanQueue = append(scanQueue, crawlResult.Links...)
				scanQueue = append(scanQueue, crawlResult.JSLinks...)
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

	// Template Loading with custom path support
	var templates []*template.Template
	pathToScan := "templates"
	if *templatePath != "" {
		pathToScan = *templatePath
	}
	filepath.Walk(pathToScan, func(path string, info os.FileInfo, err error) error {
		if err != nil { return nil }
		if !info.IsDir() && filepath.Ext(path) == ".yaml" {
			t, _ := template.Load(path)
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
				db.Update(fmt.Sprintf("Turbo Scan [%d/%d] %s", idx+1, len(finalQueue), u), progress, len(finalTargets))
			}

			for _, t := range templates {
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
		color.HiRed("\n[!!] CRITICAL: Found %d vulnerabilities!\n", len(allResults))
		engine.GenerateHTML(*target, allResults, *htmlOutput)
		if *tgToken != "" {
			engine.SendTelegramNotification(*tgToken, *tgChat, *target, allResults)
		}
	} else {
		color.Green("\n[-] Scan completed. No vulnerabilities found in %d targets.\n", len(finalQueue))
	}
}
