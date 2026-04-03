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
}

func Crawl(target string) (*CrawlResult, error) {
	fmt.Printf("[CRAWL] Starting crawl on %s\n", target)
	res, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, err
	}

	result := &CrawlResult{}
	baseURL, _ := url.Parse(target)

	// 1. Links (<a>)
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			u, err := url.Parse(href)
			if err == nil {
				abs := baseURL.ResolveReference(u).String()
				if strings.HasPrefix(abs, target) {
					result.Links = append(result.Links, abs)
				}
			}
		}
	})

	// 2. JS Files Extraction
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, _ := s.Attr("src")
		jsURL, _ := url.Parse(src)
		absJS := baseURL.ResolveReference(jsURL).String()
		
		// Fetch JS content and extract endpoints
		endpoints, _ := ExtractJSLinks(absJS)
		result.JSLinks = append(result.JSLinks, endpoints...)
	})

	// 3. Forms
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		result.Forms = append(result.Forms, fmt.Sprintf("%s (%s)", action, method))
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
	// Go's regexp doesn't support backreferences (\1), so we simplify
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
