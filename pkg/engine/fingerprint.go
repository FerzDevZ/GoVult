package engine

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Fingerprint struct {
	CMS       string
	Server    string
	PoweredBy string
	Framework string
	Techs     []string
}

func DetectTechnology(target string) (*Fingerprint, error) {
	fmt.Printf("[FINGERPRINT] Deep technology fingerprinting for %s...\n", target)
	res, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	fp := &Fingerprint{
		Server:    res.Header.Get("Server"),
		PoweredBy: res.Header.Get("X-Powered-By"),
	}

	body, _ := io.ReadAll(res.Body)
	content := string(body)

	// 1. Meta Tag & Body Check
	if strings.Contains(strings.ToLower(content), "wp-content") {
		fp.CMS = "WordPress"
	}
	if strings.Contains(strings.ToLower(content), "drupal") {
		fp.CMS = "Drupal"
	}
	if strings.Contains(strings.ToLower(content), "joomla") {
		fp.CMS = "Joomla"
	}

	// 2. JS Libs
	if strings.Contains(content, "react") || strings.Contains(content, "_next") {
		fp.Framework = "Next.js / React"
	}
	if strings.Contains(content, "vue.js") || strings.Contains(content, "vuex") {
		fp.Framework = "Vue.js"
	}
	if strings.Contains(content, "jquery.min.js") {
		fp.Techs = append(fp.Techs, "jQuery")
	}

	// 3. Header Patterns
	if strings.Contains(strings.ToLower(fp.Server), "cloudflare") {
		fp.Techs = append(fp.Techs, "Cloudflare WAF")
	}

	return fp, nil
}
