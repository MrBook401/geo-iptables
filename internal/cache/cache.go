// Package cache downloads zone files, caches them on disk, and falls back to
// stale data when the network is unavailable.
package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"geo-iptables/internal/source"
)

// Fetcher retrieves the body at url. It is injectable for offline tests.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Store manages an on-disk zone cache.
type Store struct {
	Dir     string
	MaxAge  time.Duration
	Refresh bool
	Fetch   Fetcher
	Warn    func(format string, args ...any)

	// now is injectable for tests; defaults to time.Now.
	now func() time.Time
}

// DefaultDir returns the default cache directory:
// ${XDG_CACHE_HOME:-$HOME/.cache}/geo-iptables.
func DefaultDir() string {
	if x := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME")); x != "" {
		return filepath.Join(x, "geo-iptables")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "geo-iptables-cache")
	}
	return filepath.Join(home, ".cache", "geo-iptables")
}

// FileName returns the cache filename for a country and family.
func FileName(cc string, family int) string {
	ext := "v4"
	if family == source.Family6 {
		ext = "v6"
	}
	return fmt.Sprintf("%s-%s.zone", strings.ToUpper(cc), ext)
}

func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Store) warn(format string, args ...any) {
	if s.Warn != nil {
		s.Warn(format, args...)
	}
}

// Path returns the absolute cache path for a country/family.
func (s *Store) Path(cc string, family int) string {
	return filepath.Join(s.Dir, FileName(cc, family))
}

// Load returns the zone body for a country/family. It uses a fresh cache entry
// when possible, otherwise downloads from the primary source and then the
// fallback source. On total failure it returns stale cached data with a
// warning, or an error when no cache exists.
func (s *Store) Load(ctx context.Context, cc string, family int) ([]byte, error) {
	path := s.Path(cc, family)

	cached, readErr := os.ReadFile(path)
	haveCache := readErr == nil
	fresh := false
	if haveCache {
		if fi, err := os.Stat(path); err == nil {
			fresh = s.MaxAge > 0 && s.clock().Sub(fi.ModTime()) < s.MaxAge
		}
	}

	if haveCache && fresh && !s.Refresh {
		return cached, nil
	}

	urls := []string{source.PrimaryURL(cc, family), source.FallbackURL(cc, family)}
	var lastErr error
	for i, u := range urls {
		if s.Fetch == nil {
			lastErr = errors.New("no fetcher configured")
			break
		}
		data, err := s.Fetch(ctx, u)
		if err != nil {
			lastErr = err
			s.warn("fetch %s failed: %v", u, err)
			continue
		}
		if i > 0 {
			s.warn("using fallback source %s", u)
		}
		if err := s.writeAtomic(path, data); err != nil {
			s.warn("cache write %s failed: %v", path, err)
		}
		return data, nil
	}

	if haveCache {
		s.warn("all sources failed (%v); using stale cached data for %s", lastErr, strings.ToUpper(cc))
		return cached, nil
	}
	return nil, fmt.Errorf("no cached data for %s and all sources failed: %w", strings.ToUpper(cc), lastErr)
}

// Put atomically writes body to the cache path for a country/family.
func (s *Store) Put(cc string, family int, body []byte) error {
	return s.writeAtomic(s.Path(cc, family), body)
}

func (s *Store) writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cache dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// NewHTTPFetcher returns a Fetcher using HTTPS with a 30s timeout, the given
// User-Agent, and up to 3 attempts with backoff on network errors and 5xx.
func NewHTTPFetcher(userAgent string) Fetcher {
	client := &http.Client{Timeout: 30 * time.Second}
	return func(ctx context.Context, url string) ([]byte, error) {
		var lastErr error
		for attempt := 1; attempt <= 3; attempt++ {
			if attempt > 1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(backoff(attempt)):
				}
			}
			data, retryable, err := httpGet(ctx, client, url, userAgent)
			if err == nil {
				return data, nil
			}
			lastErr = err
			if !retryable {
				break
			}
		}
		return nil, lastErr
	}
}

func backoff(attempt int) time.Duration {
	d := time.Duration(500*(1<<uint(attempt-2))) * time.Millisecond
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

func httpGet(ctx context.Context, client *http.Client, url, userAgent string) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retryable := resp.StatusCode >= 500
		return nil, retryable, fmt.Errorf("GET %s: unexpected status %s", url, resp.Status)
	}

	const maxBody = 256 << 20 // 256 MiB safety cap
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, true, fmt.Errorf("read %s: %w", url, err)
	}
	return data, false, nil
}
