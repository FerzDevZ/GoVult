package engine

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type CrawlResult struct {
	Links   []string
	Forms   []string
	Inputs  []string
	JSLinks []string
	Depth   int
}

func Crawl(target string, maxDepth int) (*CrawlResult, error) {
	return crawlRecursive(target, 0, maxDepth, make(map[string]bool))
}

func crawlRecursive(target string, currentDepth, maxDepth int, visited map[string]bool) (*CrawlResult, error) {
	if currentDepth > maxDepth || visited[target] {
		return &CrawlResult{}, nil
	}
	visited[target] = true

	fmt.Printf("[CRAWL] Scanning depth %d: %s\n", currentDepth, target)
	res, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	content := string(body)
	
	result := &CrawlResult{Depth: currentDepth}
	baseURL, _ := url.Parse(target)

	// vX: Titan SPA Detection
	isSPA := strings.Contains(content, "id=\"app\"") || strings.Contains(content, "id=\"root\"")
	if isSPA {
		fmt.Printf("[TITAN] SPA detected! Switching to Headless Crawler (Chromedp)...\n")
		hLinks, _ := HeadlessCrawl(target)
		result.Links = append(result.Links, hLinks...)
	}

	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(content))

	// 1. Links (<a>)
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			u, err := url.Parse(href)
			if err == nil {
				abs := baseURL.ResolveReference(u).String()
				if strings.HasPrefix(abs, target) {
					result.Links = append(result.Links, abs)
					
					// Recursive Crawl
					if currentDepth < maxDepth {
						subRes, _ := crawlRecursive(abs, currentDepth+1, maxDepth, visited)
						if subRes != nil {
							result.Links = append(result.Links, subRes.Links...)
							result.JSLinks = append(result.JSLinks, subRes.JSLinks...)
						}
					}
				}
			}
		}
	})

	// 2. JS Files Extraction
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, _ := s.Attr("src")
		jsURL, _ := url.Parse(src)
		absJS := baseURL.ResolveReference(jsURL).String()
		
		endpoints, _ := ExtractJSLinks(absJS)
		result.JSLinks = append(result.JSLinks, endpoints...)
	})

	return result, nil
}

// ExtractJSLinks uses regex to find API endpoints and relative paths in JS files
func ExtractJSLinks(jsURL string) ([]string, error) {
	resp, err := http.Get(jsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	// Regex for relative paths: /path/to/api, ./path/to/api, ../path/to/api
	re := regexp.MustCompile(`["'` + "`" + `](/?(?:[\w.-]+/?)+)["'` + "`" + `]`)
	matches := re.FindAllStringSubmatch(content, -1)

	var endpoints []string
	for _, m := range matches {
		if len(m) > 1 {
			endpoints = append(endpoints, m[1])
		}
	}
	return endpoints, nil
}
