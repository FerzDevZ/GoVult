package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/FerzDevZ/GoVult/pkg/engine"
	"github.com/FerzDevZ/GoVult/pkg/template"
)

func main() {
	target := flag.String("u", "", "Target URL")
	templatePath := flag.String("t", "", "Path to template file or directory")
	fullScan := flag.Bool("full", false, "Enable full scanning (Templates + Discovery)")
	rateLimit := flag.Int("rl", 5, "Rate limit (Requests Per Second)")
	htmlOutput := flag.String("o", "report.html", "Path to save HTML report")
	tgToken := flag.String("tg-token", "", "Telegram Bot Token")
	tgChat := flag.String("tg-chat", "", "Telegram Chat ID")
	proxy := flag.String("proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: govult -u <target> [-t <template>] [--full] [-rl <rps>] [-o report.html] [--tg-token <token>] [--tg-chat <chat_id>] [--proxy http://...]")
		os.Exit(1)
	}

	// Branding
	headerColor := color.New(color.FgCyan, color.Bold)
	headerColor.Println("GoVult v2.0 Master Edition")
	color.Green("[*] Starting scanner for: %s\n", *target)

	// Create Engine
	govultEngine := engine.NewEngine(*rateLimit, *proxy)

	var templates []*template.Template

	// 1. Load Templates
	if *templatePath != "" {
		t, err := template.Load(*templatePath)
		if err == nil {
			templates = append(templates, t)
		} else {
			files, _ := filepath.Glob(filepath.Join(*templatePath, "*.yaml"))
			for _, file := range files {
				t, err := template.Load(file)
				if err == nil {
					templates = append(templates, t)
				}
			}
		}
	} else if *fullScan {
		files, _ := filepath.Glob("templates/basic/*.yaml")
		for _, file := range files {
			t, err := template.Load(file)
			if err == nil {
				templates = append(templates, t)
			}
		}
	}

	// 2. Run Vulnerability Scanning
	var allResults []engine.Result
	for _, t := range templates {
		color.Blue("[*] Running module: [%s] %s\n", t.ID, t.Info.Name)
		results, err := govultEngine.Run(*target, t)
		if err != nil {
			color.Red("[!] Error running module %s: %v\n", t.ID, err)
			continue
		}
		allResults = append(allResults, results...)
	}

	// 3. Discovery (only if fullScan is enabled)
	if *fullScan {
		color.Yellow("[*] Starting Discovery Module...")
		commonPaths := []string{".env", ".git/config", "admin", "config", "phpinfo.php"}
		discoveryResults, _ := engine.Fuzz(*target, commonPaths)
		if len(discoveryResults) > 0 {
			fmt.Printf("\n[+] Discovery Found %d assets:\n", len(discoveryResults))
			for _, dr := range discoveryResults {
				color.HiGreen("    - [DISCOVERY] %s (%d)\n", dr.Path, dr.StatusCode)
			}
		}
	}

	// 4. Summarize results
	if len(allResults) > 0 {
		color.HiRed("\n[+] GoVult found %d vulnerabilities:\n", len(allResults))
		for _, r := range allResults {
			fmt.Printf("    - [%s] %s (Severity: %s)\n", r.TemplateID, r.Target, r.Severity)
		}

		// 5. Generate Premium Report
		err := engine.GenerateHTML(*target, allResults, *htmlOutput)
		if err != nil {
			color.Red("[!] Error generating report: %v\n", err)
		} else {
			color.HiMagenta("\n[✓] Premium HTML report generated: %s\n", *htmlOutput)
		}

		// 6. Telegram Notification
		if *tgToken != "" && *tgChat != "" {
			err := engine.SendTelegramNotification(*tgToken, *tgChat, *target, allResults)
			if err != nil {
				color.Red("[!] Error sending Telegram notification: %v\n", err)
			} else {
				color.HiCyan("[✓] Telegram notification sent successfully!\n")
			}
		}

	} else {
		fmt.Println("\n[-] No vulnerabilities found by templates.")
	}
}
