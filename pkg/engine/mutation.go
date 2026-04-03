package engine

import (
	"net/url"
	"strings"
)

func MutatePayload(payload string) []string {
	var mutations []string
	mutations = append(mutations, payload)

	// URL Encoding
	encoded := url.QueryEscape(payload)
	if encoded != payload {
		mutations = append(mutations, encoded)
	}

	// Double URL Encoding
	doubleEncoded := url.QueryEscape(encoded)
	if doubleEncoded != encoded {
		mutations = append(mutations, doubleEncoded)
	}

	// HTML Encoding (Basic)
	htmlEncoded := strings.NewReplacer("<", "&lt;", ">", "&gt;", "'", "&#39;", "\"", "&quot;").Replace(payload)
	if htmlEncoded != payload {
		mutations = append(mutations, htmlEncoded)
	}

	return mutations
}
