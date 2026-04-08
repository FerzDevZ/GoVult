package template

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var template Template
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, err
	}

	if err := validateTemplate(&template); err != nil {
		return nil, err
	}

	return &template, nil
}

func validateTemplate(t *Template) error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("template id is required")
	}
	if len(t.Requests) == 0 {
		return fmt.Errorf("template %s must define at least one request", t.ID)
	}
	for i, req := range t.Requests {
		if strings.TrimSpace(req.Method) == "" {
			return fmt.Errorf("template %s request[%d]: method is required", t.ID, i)
		}
		if len(req.Path) == 0 {
			return fmt.Errorf("template %s request[%d]: path is required", t.ID, i)
		}
	}
	return nil
}
