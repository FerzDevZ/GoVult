package engine

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/FerzDevZ/GoVult/pkg/template"
	"github.com/PuerkitoBio/goquery"
	"github.com/tidwall/gjson"
)

// Match implements "AND" logic among top-level matchers.
// All matchers in the list must be true for the result to be matched.
<<<<<<< HEAD
func Match(respBody string, statusCode int, duration float64, matchers []template.Matcher) bool {
=======
func Match(respBody string, respHeader http.Header, statusCode int, matchers []template.Matcher) bool {
>>>>>>> 8aaf884 (new update)
	if len(matchers) == 0 {
		return false
	}

	for _, matcher := range matchers {
		matched := false
		part := strings.ToLower(strings.TrimSpace(matcher.Part))
		haystack := respBody
		if part == "header" {
			haystack = strings.ToLower(respHeader.String())
		}

		switch matcher.Type {
		case "status":
			for _, s := range matcher.Status {
				if s == statusCode {
					matched = true
					break
				}
			}
		case "word":
			if matcher.Condition == "and" {
				matched = true
				for _, word := range matcher.Words {
					needle := word
					if part == "header" {
						needle = strings.ToLower(word)
					}
					if !strings.Contains(haystack, needle) {
						matched = false
						break
					}
				}
			} else { // default to "or"
				for _, word := range matcher.Words {
					needle := word
					if part == "header" {
						needle = strings.ToLower(word)
					}
					if strings.Contains(haystack, needle) {
						matched = true
						break
					}
				}
			}
		case "regex":
			for _, reStr := range matcher.Regex {
				re, err := regexp.Compile(reStr)
				if err != nil {
					continue
				}
				if re.MatchString(haystack) {
					matched = true
					break
				}
			}
		case "size":
			for _, s := range matcher.Size {
				if len(respBody) == s {
					matched = true
					break
				}
			}
		case "css":
			if part == "header" {
				continue
			}
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(respBody))
			if err != nil {
				continue
			}
			for _, selector := range matcher.CSS {
				if doc.Find(selector).Length() > 0 {
					matched = true
					break
				}
			}
		case "json":
			if part == "header" {
				continue
			}
			for _, path := range matcher.JSON {
				result := gjson.Get(respBody, path)
				if result.Exists() {
					matched = true
					break
				}
			}
		case "duration":
			if duration >= float64(matcher.Duration) {
				matched = true
			}
		}

		if matcher.Negative {
			matched = !matched
		}

		// If ANY matcher fails, the whole request fails the "AND" logic.
		if !matched {
			return false
		}
	}
	// All matchers were true.
	return true
}
