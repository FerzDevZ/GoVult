package engine

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type PortResult struct {
	Port    int
	Status  string
	Service string
}

func ScanPorts(host string, ports []int) []PortResult {
	var results []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Built-in Top Services Map
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 443: "HTTPS", 3306: "MySQL", 6379: "Redis",
		27017: "MongoDB", 5432: "PostgreSQL", 8080: "HTTP-Proxy",
	}

	portsChan := make(chan int, 100)
	concurrency := 100
	semaphore := make(chan struct{}, concurrency)

	fmt.Printf("[PORTSCAN] Starting infrastructure reconnaissance for %s...\n", host)

	go func() {
		for _, p := range ports {
			portsChan <- p
		}
		close(portsChan)
	}()

	for p := range portsChan {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			address := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				results = append(results, PortResult{
					Port:    port,
					Status:  "OPEN",
					Service: services[port],
				})
				mu.Unlock()
				fmt.Printf("    - [PORT] %d is OPEN (%s)\n", port, services[port])
			}
		}(p)
	}

	wg.Wait()
	return results
}
