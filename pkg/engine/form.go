package engine

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type Form struct {
	Action string
	Method string
	Inputs []string
}

func ExtractForms(target string) ([]Form, error) {
	res, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, err
	}

	var forms []Form
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		if method == "" {
			method = "GET"
		}
		
		var inputs []string
		s.Find("input, textarea").Each(func(j int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			if name != "" {
				inputs = append(inputs, name)
			}
		})

		forms = append(forms, Form{
			Action: action,
			Method: strings.ToUpper(method),
			Inputs: inputs,
		})
	})

	return forms, nil
}

func (e *Engine) ExploitForm(target string, f Form, payload string) (*Result, error) {
	// Build target URL for the action
	u, _ := url.Parse(target)
	actionURL, _ := url.Parse(f.Action)
	absAction := u.ResolveReference(actionURL).String()

	data := url.Values{}
	for _, input := range f.Inputs {
		data.Set(input, payload)
	}

	var resp *http.Response
	var err error

	if f.Method == "POST" {
		resp, err = e.Client.PostForm(absAction, data)
	} else {
		// GET with parameters
		u, _ := url.Parse(absAction)
		u.RawQuery = data.Encode()
		resp, err = e.Client.Get(u.String())
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Simple check (could be improved with template matchers later)
	if resp.StatusCode == 200 || resp.StatusCode == 500 {
		// Successful submission, return indicator
		return &Result{
			TemplateID: "form-injection",
			Target:     absAction,
			Severity:   "high",
			Matched:    true,
		}, nil
	}

	return nil, nil
}
