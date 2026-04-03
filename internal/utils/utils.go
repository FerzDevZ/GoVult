package utils

import (
	"bufio"
	"net/url"
	"os"
	"strings"
)

func LoadProxies(path string) ([]*url.URL, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []*url.URL
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		u, err := url.Parse(line)
		if err != nil {
			continue // Skip invalid proxies
		}
		proxies = append(proxies, u)
	}
	return proxies, scanner.Err()
}

func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}
