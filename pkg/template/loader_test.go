package template

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.yaml")
	content := []byte(`
id: test-id
info:
  name: demo
  author: test
  severity: low
  description: demo
requests:
  - method: GET
    path: ["/"]
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("expected valid template, got error: %v", err)
	}
}

func TestLoadInvalidTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	content := []byte(`
id: ""
info:
  name: bad
  author: test
  severity: low
  description: demo
requests: []
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error, got nil")
	}
}
