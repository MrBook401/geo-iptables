// Package source renders zone URLs and parses zone files into netip prefixes.
package source

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Address families.
const (
	Family4 = 4
	Family6 = 6
)

// AllZonesV4URL is the ipdeny tarball containing every IPv4 country zone.
const AllZonesV4URL = "https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz"

// PrimaryURL returns the ipdeny.com aggregated-zone URL for a country/family.
// ipdeny serves lowercase two-letter filenames.
func PrimaryURL(cc string, family int) string {
	cc = strings.ToLower(strings.TrimSpace(cc))
	if family == Family6 {
		return fmt.Sprintf("https://www.ipdeny.com/ipv6/ipaddresses/aggregated/%s-aggregated.zone", cc)
	}
	return fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone", cc)
}

// FallbackURL returns the ipverse/rir-ip URL for a country/family.
func FallbackURL(cc string, family int) string {
	cc = strings.ToLower(strings.TrimSpace(cc))
	kind := "ipv4"
	if family == Family6 {
		kind = "ipv6"
	}
	return fmt.Sprintf("https://raw.githubusercontent.com/ipverse/rir-ip/master/country/%s/%s-aggregated.txt", cc, kind)
}

// Result is the outcome of parsing a zone file.
type Result struct {
	Prefixes   []netip.Prefix
	Invalid    int
	Duplicates int
}

// Parse reads a zone file and returns the prefixes belonging to family.
// Blank lines and lines starting with '#' are skipped. Invalid lines and
// lines belonging to the wrong family are counted and skipped. Prefixes are
// masked to their network address and de-duplicated.
func Parse(r io.Reader, family int) (Result, error) {
	var res Result
	seen := make(map[netip.Prefix]bool)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			res.Invalid++
			continue
		}
		p = p.Masked()
		if family == Family4 && !p.Addr().Is4() {
			res.Invalid++
			continue
		}
		if family == Family6 && !p.Addr().Is6() {
			res.Invalid++
			continue
		}
		if seen[p] {
			res.Duplicates++
			continue
		}
		seen[p] = true
		res.Prefixes = append(res.Prefixes, p)
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("read zone: %w", err)
	}
	return res, nil
}
