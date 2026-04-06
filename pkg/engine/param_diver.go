package engine

import (
	"fmt"
	"sync"
	"time"
)

// ParamDiver mining hidden parameters for unauthorized access
func (e *Engine) ParamDiver(target string) []string {
	fmt.Printf("[PARAM-DIVER] Mining hidden parameters via concurrent behavioral diffing...\n")
	var foundParams []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Common hidden parameters
	params := []string{"debug", "admin", "test", "dev", "v", "cfg", "show", "internal"}

	// 1. Get baseline (Normal Response)
	resp1, err := e.Client.Get(target)
	if err != nil {
		return nil
	}
	defer resp1.Body.Close()
	baselineLen := resp1.ContentLength

	// 2. Probe each parameter
	for _, p := range params {
		wg.Add(1)
		go func(param string) {
			defer wg.Done()
			u := fmt.Sprintf("%s?%s=1", target, param)
			resp2, err := e.Client.Get(u)
			if err != nil { return }
			defer resp2.Body.Close()

			// 3. Behavioral Diffing (Length changes + Header changes)
			if resp2.ContentLength != baselineLen || resp2.StatusCode != resp1.StatusCode {
				mu.Lock()
				fmt.Printf("    [!] Found hidden parameter: %s (Behavioral change detected!)\n", param)
				foundParams = append(foundParams, param)
				mu.Unlock()
			}
		}(p)
		time.Sleep(10 * time.Millisecond) // micro-throttle
	}
	wg.Wait()

	return foundParams
}
