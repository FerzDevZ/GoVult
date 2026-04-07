package engine

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
	"github.com/FerzDevZ/GoVult/pkg/template"
)

type AttackChain struct {
	ID          string             `yaml:"id"`
	Description string             `yaml:"description"`
	Condition   []string           `yaml:"condition"`
	Steps       []template.Request `yaml:"steps"`
}

func LoadChains(dir string) ([]AttackChain, error) {
	var chains []AttackChain
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var c []AttackChain
			if err := yaml.Unmarshal(data, &c); err != nil {
				// Try unmarshaling as a single chain
				var sc AttackChain
				if err := yaml.Unmarshal(data, &sc); err == nil {
					chains = append(chains, sc)
				}
				return nil
			}
			chains = append(chains, c...)
		}
		return nil
	})
	return chains, err
}
