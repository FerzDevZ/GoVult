package engine

import (
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/FerzDevZ/GoVult/pkg/template"
	"github.com/tidwall/gjson"
)

// Match implements "AND" logic among top-level matchers.
// All matchers in the list must be true for the result to be matched.
func Match(respBody string, statusCode int, duration float64, matchers []template.Matcher) bool {
	if len(matchers) == 0 {
		return false
	}

	for _, matcher := range matchers {
		matched := false
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
					if !strings.Contains(respBody, word) {
						matched = false
						break
					}
				}
			} else { // default to "or"
				for _, word := range matcher.Words {
					if strings.Contains(respBody, word) {
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
				if re.MatchString(respBody) {
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

		// If ANY matcher fails, the whole request fails the "AND" logic.
		if !matched {
			return false
		}
	}
	// All matchers were true.
	return true
}
