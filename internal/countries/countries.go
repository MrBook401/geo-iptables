// Package countries normalizes and validates ISO 3166-1 alpha-2 country codes.
package countries

import (
	"fmt"
	"regexp"
	"strings"
)

var codeRe = regexp.MustCompile(`^[A-Z]{2}$`)

// Parse splits a comma-separated list of country codes and normalizes it.
// Whitespace-only entries are ignored. It returns an error for any entry that
// is not exactly two ASCII letters after trimming/uppercasing.
func Parse(csv string) ([]string, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	return Normalize(strings.Split(csv, ","))
}

// Normalize trims, uppercases, validates and de-duplicates codes while
// preserving first-seen order. Empty entries are skipped.
func Normalize(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		code := strings.ToUpper(strings.TrimSpace(raw))
		if code == "" {
			continue
		}
		if !codeRe.MatchString(code) {
			return nil, fmt.Errorf("invalid country code %q: expected two letters (e.g. CH)", strings.TrimSpace(raw))
		}
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out, nil
}
