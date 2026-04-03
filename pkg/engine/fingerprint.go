package engine

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type Fingerprint struct {
	CMS        string
	Server     string
	PoweredBy  string
	Framework  string
}

func DetectTechnology(target string) (*Fingerprint, error) {
	fmt.Printf("[FINGERPRINT] Detecting technology for %s\n", target)
	res, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	fp := &Fingerprint{
		Server:    res.Header.Get("Server"),
		PoweredBy: res.Header.Get("X-Powered-By"),
	}

	// 1. Meta Tag Check (using goquery)
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err == nil {
		doc.Find("meta[name='generator']").Each(func(i int, s *goquery.Selection) {
			content, _ := s.Attr("content")
			if strings.Contains(strings.ToLower(content), "wordpress") {
				fp.CMS = "WordPress"
			}
		})
	}

	// 2. Common Patterns
	if strings.Contains(strings.ToLower(fp.PoweredBy), "php") {
		fp.Framework = "PHP"
	}
	if strings.Contains(strings.ToLower(fp.Server), "nginx") {
		fp.Server = "Nginx"
	}

	return fp, nil
}
