package cache

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"geo-iptables/internal/countries"
)

// ImportResult summarizes an ImportArchive run.
type ImportResult struct {
	Countries []string // uppercase codes imported, in archive order
	Skipped   int      // archive members that were not valid country zones
	Bytes     int64    // total zone payload bytes written
}

// ImportArchive downloads a tar.gz of <cc>.zone files and writes each valid
// country zone to the cache for family. filter, when non-empty, restricts the
// import to those country codes (case-insensitive). s.Fetch must be set.
func (s *Store) ImportArchive(ctx context.Context, url string, family int, filter []string) (ImportResult, error) {
	var res ImportResult
	if s.Fetch == nil {
		return res, errors.New("no fetcher configured")
	}

	var allowed map[string]bool
	if len(filter) > 0 {
		norm, err := countries.Normalize(filter)
		if err != nil {
			return res, err
		}
		allowed = make(map[string]bool, len(norm))
		for _, cc := range norm {
			allowed[cc] = true
		}
	}

	data, err := s.Fetch(ctx, url)
	if err != nil {
		return res, fmt.Errorf("fetch %s: %w", url, err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return res, fmt.Errorf("open gzip %s: %w", url, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	seen := make(map[string]bool)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, fmt.Errorf("read archive %s: %w", url, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			res.Skipped++
			continue
		}

		name := path.Base(hdr.Name)
		if !strings.HasSuffix(name, ".zone") {
			res.Skipped++
			continue
		}
		base := strings.TrimSuffix(name, ".zone")
		codes, err := countries.Normalize([]string{base})
		if err != nil || len(codes) == 0 {
			res.Skipped++
			continue
		}
		cc := codes[0]
		if allowed != nil && !allowed[cc] {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(tr, 32<<20))
		if err != nil {
			return res, fmt.Errorf("read member %s: %w", hdr.Name, err)
		}
		if err := s.Put(cc, family, body); err != nil {
			return res, fmt.Errorf("cache %s: %w", cc, err)
		}
		res.Bytes += int64(len(body))
		if !seen[cc] {
			seen[cc] = true
			res.Countries = append(res.Countries, cc)
		}
	}
	return res, nil
}
