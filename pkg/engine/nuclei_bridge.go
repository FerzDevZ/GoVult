package engine

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/FerzDevZ/GoVult/pkg/template"
	"gopkg.in/yaml.v3"
)

// NucleiTemplate represents a simplified Nuclei YAML structure
type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
	} `yaml:"info"`
	HTTP []struct {
		Method    string            `yaml:"method"`
		Path      []string          `yaml:"path"`
		Headers   map[string]string `yaml:"headers"`
		Body      string            `yaml:"body"`
		Matchers  []NucleiMatcher   `yaml:"matchers"`
	} `yaml:"http"`
}

type NucleiMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"`
}

// LoadNuclei loads and converts a Nuclei template to a GoVult template
func LoadNuclei(path string) (*template.Template, error) {
	if filepath.Ext(path) != ".yaml" {
		return nil, fmt.Errorf("not a yaml file")
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var nt NucleiTemplate
	err = yaml.Unmarshal(data, &nt)
	if err != nil {
		return nil, err
	}

	// Simple conversion logic
	if len(nt.HTTP) == 0 {
		return nil, fmt.Errorf("no http blocks found in nuclei template")
	}

	t := &template.Template{
		ID: nt.ID,
	}
	t.Info.Name = nt.Info.Name
	t.Info.Severity = nt.Info.Severity

	// Map Nuclei HTTP to GoVult Template.Requests
	// (GoVult currently supports one request list per template, so we take the first Nuclei HTTP block)
	block := nt.HTTP[0]
	req := template.Request{
		Method:  block.Method,
		Path:    block.Path,
		Headers: block.Headers,
		Body:    block.Body,
	}

	for _, nm := range block.Matchers {
		m := template.Matcher{
			Type:      nm.Type,
			Words:     nm.Words,
			Status:    nm.Status,
			Condition: nm.Condition,
		}
		req.Matchers = append(req.Matchers, m)
	}

	t.Requests = append(t.Requests, req)

	return t, nil
}
