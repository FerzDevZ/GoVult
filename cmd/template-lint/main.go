package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	gtemplate "github.com/FerzDevZ/GoVult/pkg/template"
)

func main() {
	dir := flag.String("dir", "templates", "Template directory to lint")
	flag.Parse()

	var checked int
	var failed int

	_ = filepath.Walk(*dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			failed++
			fmt.Printf("[ERR] %s: %v\n", path, err)
			return nil
		}
		if info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		checked++
		if _, err := gtemplate.Load(path); err != nil {
			failed++
			fmt.Printf("[FAIL] %s: %v\n", path, err)
			return nil
		}
		fmt.Printf("[OK] %s\n", path)
		return nil
	})

	fmt.Printf("\nChecked: %d | Failed: %d\n", checked, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
