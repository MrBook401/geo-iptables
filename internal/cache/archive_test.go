package cache

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"geo-iptables/internal/source"
)

// makeTarGz builds an in-memory gzipped tar with the given members (written as
// regular files in sorted name order).
func makeTarGz(t *testing.T, members map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		body := members[name]
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
		if strings.HasSuffix(name, "/") {
			// Directories (e.g. "./") cannot carry content or be TypeReg.
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
			hdr.Size = 0
			body = ""
		} else {
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if body == "" {
			continue
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func fetchBytes(data []byte) Fetcher {
	return func(context.Context, string) ([]byte, error) { return data, nil }
}

func TestImportArchiveValid(t *testing.T) {
	archive := makeTarGz(t, map[string]string{
		"./":        "junk",
		"./.zone":   "junk",
		"./ch.zone": "1.2.3.0/24\n",
		"./us.zone": "5.6.7.0/24\n",
	})
	dir := t.TempDir()
	s := &Store{Dir: dir, Fetch: fetchBytes(archive)}

	res, err := s.ImportArchive(context.Background(), "https://example/all.tar.gz", source.Family4, nil)
	if err != nil {
		t.Fatalf("ImportArchive: %v", err)
	}
	if res.Skipped != 2 {
		t.Fatalf("Skipped = %d, want 2", res.Skipped)
	}
	if want := []string{"CH", "US"}; !equalStrings(res.Countries, want) {
		t.Fatalf("Countries = %v, want %v", res.Countries, want)
	}
	if want := int64(len("1.2.3.0/24\n") + len("5.6.7.0/24\n")); res.Bytes != want {
		t.Fatalf("Bytes = %d, want %d", res.Bytes, want)
	}

	assertFile(t, filepath.Join(dir, FileName("CH", source.Family4)), "1.2.3.0/24\n")
	assertFile(t, filepath.Join(dir, FileName("US", source.Family4)), "5.6.7.0/24\n")
}

func TestImportArchiveFilter(t *testing.T) {
	archive := makeTarGz(t, map[string]string{
		"./ch.zone": "1.2.3.0/24\n",
		"./us.zone": "5.6.7.0/24\n",
	})
	dir := t.TempDir()
	s := &Store{Dir: dir, Fetch: fetchBytes(archive)}

	res, err := s.ImportArchive(context.Background(), "https://example/all.tar.gz", source.Family4, []string{"ch"})
	if err != nil {
		t.Fatalf("ImportArchive: %v", err)
	}
	if want := []string{"CH"}; !equalStrings(res.Countries, want) {
		t.Fatalf("Countries = %v, want %v", res.Countries, want)
	}
	if res.Skipped != 0 {
		t.Fatalf("Skipped = %d, want 0 (filtered members are not skipped)", res.Skipped)
	}
	assertFile(t, filepath.Join(dir, FileName("CH", source.Family4)), "1.2.3.0/24\n")
	if _, err := os.Stat(filepath.Join(dir, FileName("US", source.Family4))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("US zone stat err = %v, want not-exist", err)
	}
}

func TestImportArchiveCorruptGzip(t *testing.T) {
	s := &Store{Dir: t.TempDir(), Fetch: fetchBytes([]byte("this is not gzip"))}
	if _, err := s.ImportArchive(context.Background(), "u", source.Family4, nil); err == nil {
		t.Fatal("ImportArchive: want error for corrupt gzip, got nil")
	}
}

func TestImportArchiveFetchError(t *testing.T) {
	s := &Store{Dir: t.TempDir(), Fetch: func(context.Context, string) ([]byte, error) {
		return nil, errors.New("boom")
	}}
	if _, err := s.ImportArchive(context.Background(), "u", source.Family4, nil); err == nil {
		t.Fatal("ImportArchive: want fetch error, got nil")
	}
}

func TestImportArchiveNilFetch(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if _, err := s.ImportArchive(context.Background(), "u", source.Family4, nil); err == nil {
		t.Fatal("ImportArchive: want no-fetcher error, got nil")
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
