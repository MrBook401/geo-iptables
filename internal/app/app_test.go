package app

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
	"time"

	"geo-iptables/internal/cache"
	"geo-iptables/internal/firewall"
	"geo-iptables/internal/source"
	"geo-iptables/internal/version"
)

type runResult struct {
	code   int
	stdout string
	stderr string
}

func runCLI(t *testing.T, d deps, args ...string) runResult {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, d)
	return runResult{code: code, stdout: out.String(), stderr: errb.String()}
}

// testDeps returns deps that never touch the network, report root, and use the
// supplied runner.
func testDeps(r firewall.Runner) deps {
	return deps{
		runner: r,
		euid:   func() int { return 0 },
		now:    time.Now,
		newFetcher: func(string) cache.Fetcher {
			return func(context.Context, string) ([]byte, error) {
				return nil, errors.New("network disabled in tests")
			}
		},
	}
}

func seedZone(t *testing.T, dir, cc string, family int, body string) {
	t.Helper()
	path := filepath.Join(dir, cache.FileName(cc, family))
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("seed zone %s: %v", path, err)
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// findCall returns the first recorded call satisfying pred.
func findCall(calls []firewall.Call, pred func(firewall.Call) bool) (firewall.Call, bool) {
	for _, c := range calls {
		if pred(c) {
			return c, true
		}
	}
	return firewall.Call{}, false
}

func TestVersion(t *testing.T) {
	r := runCLI(t, testDeps(&firewall.FakeRunner{}), "version")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, version.Version) {
		t.Fatalf("stdout = %q, want it to contain %q", r.stdout, version.Version)
	}
}

func TestNoArgs(t *testing.T) {
	r := runCLI(t, testDeps(&firewall.FakeRunner{}))
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2", r.code)
	}
	if !strings.Contains(r.stderr, "Usage") {
		t.Fatalf("stderr = %q, want usage text", r.stderr)
	}
}

func TestUnknownCommand(t *testing.T) {
	r := runCLI(t, testDeps(&firewall.FakeRunner{}), "frobnicate")
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr=%q)", r.code, r.stderr)
	}
}

func TestBlockNoCountries(t *testing.T) {
	r := runCLI(t, testDeps(&firewall.FakeRunner{}), "block")
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr=%q)", r.code, r.stderr)
	}
}

func TestBlockInvalidCountry(t *testing.T) {
	r := runCLI(t, testDeps(&firewall.FakeRunner{}), "block", "ZZZ")
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr=%q)", r.code, r.stderr)
	}
}

func TestBlockCH(t *testing.T) {
	dir := t.TempDir()
	seedZone(t, dir, "CH", source.Family4, "1.2.3.0/24\n5.6.7.0/24\n")
	fr := &firewall.FakeRunner{}

	r := runCLI(t, testDeps(fr), "block", "CH", "--v4", "--cache-dir", dir, "--max-age", "1000h")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "CH v4: 2 prefixes") {
		t.Fatalf("stdout = %q, want CH count line", r.stdout)
	}

	restore, ok := findCall(fr.Calls, func(c firewall.Call) bool {
		return c.Name == "ipset" && len(c.Args) > 0 && c.Args[0] == "restore" &&
			strings.Contains(c.Stdin, "1.2.3.0/24") && strings.Contains(c.Stdin, "5.6.7.0/24")
	})
	if !ok {
		t.Fatalf("no ipset restore call carrying seeded prefixes; calls=%+v", fr.Calls)
	}
	if !strings.Contains(restore.Stdin, "geoip_block4") {
		t.Fatalf("restore stdin = %q, want geoip_block4 target", restore.Stdin)
	}

	_, ok = findCall(fr.Calls, func(c firewall.Call) bool {
		return c.Name == "iptables" && len(c.Args) >= 4 && c.Args[0] == "-A" && c.Args[1] == firewall.ChainName &&
			hasArg(c.Args, "--match-set") && hasArg(c.Args, "geoip_block4") && hasArg(c.Args, "src") && hasArg(c.Args, "DROP")
	})
	if !ok {
		t.Fatalf("no -A GEOBLOCK DROP rule using geoip_block4; calls=%+v", fr.Calls)
	}
}

func TestApplyAllowCH(t *testing.T) {
	dir := t.TempDir()
	seedZone(t, dir, "CH", source.Family4, "1.2.3.0/24\n")
	fr := &firewall.FakeRunner{}

	r := runCLI(t, testDeps(fr), "apply", "--allow", "CH", "--cache-dir", dir, "--max-age", "1000h")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}

	_, ok := findCall(fr.Calls, func(c firewall.Call) bool {
		return c.Name == "iptables" && len(c.Args) >= 4 && c.Args[0] == "-A" && c.Args[1] == firewall.ChainName &&
			hasArg(c.Args, "--match-set") && hasArg(c.Args, "geoip_allow4") && hasArg(c.Args, "RETURN")
	})
	if !ok {
		t.Fatalf("no allow RETURN rule using geoip_allow4; calls=%+v", fr.Calls)
	}
	_, ok = findCall(fr.Calls, func(c firewall.Call) bool {
		return c.Name == "iptables" && len(c.Args) == 4 && c.Args[0] == "-A" &&
			c.Args[1] == firewall.ChainName && c.Args[2] == "-j" && c.Args[3] == "DROP"
	})
	if !ok {
		t.Fatalf("no final -j DROP rule; calls=%+v", fr.Calls)
	}
}

func TestApplyRequiresAllowOrBlock(t *testing.T) {
	r := runCLI(t, testDeps(&firewall.FakeRunner{}), "apply")
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr=%q)", r.code, r.stderr)
	}
}

func TestFlush(t *testing.T) {
	fr := &firewall.FakeRunner{}
	r := runCLI(t, testDeps(fr), "flush", "--v4")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	_, ok := findCall(fr.Calls, func(c firewall.Call) bool {
		return c.Name == "iptables" && len(c.Args) == 4 && c.Args[0] == "-D" &&
			c.Args[1] == "INPUT" && c.Args[2] == "-j" && c.Args[3] == firewall.ChainName
	})
	if !ok {
		t.Fatalf("no iptables -D INPUT -j GEOBLOCK call; calls=%+v", fr.Calls)
	}
	_, ok = findCall(fr.Calls, func(c firewall.Call) bool {
		return c.Name == "ipset" && len(c.Args) == 2 && c.Args[0] == "destroy" && c.Args[1] == "geoip_block4"
	})
	if !ok {
		t.Fatalf("no ipset destroy geoip_block4 call; calls=%+v", fr.Calls)
	}
}

func TestStatus(t *testing.T) {
	fr := &firewall.FakeRunner{Respond: func(name string, args []string, _ string) (string, error) {
		if name == "ipset" && len(args) >= 2 && args[0] == "list" && args[1] == "geoip_block4" {
			return "Number of entries: 42\n", nil
		}
		return "", nil
	}}
	r := runCLI(t, testDeps(fr), "status", "--v4")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "42") {
		t.Fatalf("stdout = %q, want entry count 42", r.stdout)
	}
}

func TestSSHExempt(t *testing.T) {
	dir := t.TempDir()
	seedZone(t, dir, "CH", source.Family4, "1.2.3.0/24\n")
	fr := &firewall.FakeRunner{}

	r := runCLI(t, testDeps(fr), "block", "CH", "--ssh-exempt", "1.2.3.4,192.168.1.1/24",
		"--cache-dir", dir, "--max-age", "1000h")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	_, ok := findCall(fr.Calls, func(c firewall.Call) bool {
		return c.Name == "ipset" && len(c.Args) > 0 && c.Args[0] == "restore" &&
			strings.Contains(c.Stdin, "geoip_ssh_exempt4") && strings.Contains(c.Stdin, "1.2.3.4/32") &&
			strings.Contains(c.Stdin, "192.168.1.0/24")
	})
	if !ok {
		t.Fatalf("no ssh-exempt restore carrying 1.2.3.4/32 and 192.168.1.0/24; calls=%+v", fr.Calls)
	}

	r = runCLI(t, testDeps(&firewall.FakeRunner{}), "block", "CH", "--ssh-exempt", "nope",
		"--cache-dir", dir, "--max-age", "1000h")
	if r.code != 1 {
		t.Fatalf("invalid ssh-exempt: exit code = %d, want 1 (stderr=%q)", r.code, r.stderr)
	}
}

func TestRootRequired(t *testing.T) {
	dir := t.TempDir()
	seedZone(t, dir, "CH", source.Family4, "1.2.3.0/24\n")
	d := testDeps(&firewall.FakeRunner{})
	d.euid = func() int { return 1000 }

	r := runCLI(t, d, "block", "CH", "--cache-dir", dir, "--max-age", "1000h")
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr=%q)", r.code, r.stderr)
	}
	if !strings.Contains(strings.ToLower(r.stderr), "root") && !strings.Contains(r.stderr, "sudo") {
		t.Fatalf("stderr = %q, want a root/sudo hint", r.stderr)
	}
}

func TestFetchFailure(t *testing.T) {
	d := testDeps(&firewall.FakeRunner{})
	d.newFetcher = func(string) cache.Fetcher {
		return func(context.Context, string) ([]byte, error) {
			return nil, errors.New("offline")
		}
	}
	dir := t.TempDir()

	r := runCLI(t, d, "block", "CH", "--cache-dir", dir, "--max-age", "1000h")
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr=%q)", r.code, r.stderr)
	}
}

// makeTarGz builds an in-memory gzipped tar with the given members, written as
// regular files in sorted name order.
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
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", name, err)
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

func archiveFetcher(archive []byte) func(string) cache.Fetcher {
	return func(string) cache.Fetcher {
		return func(context.Context, string) ([]byte, error) { return archive, nil }
	}
}

func TestUpdateAllZones(t *testing.T) {
	archive := makeTarGz(t, map[string]string{
		"./ch.zone": "1.2.3.0/24\n",
		"./us.zone": "5.6.7.0/24\n",
	})
	dir := t.TempDir()
	d := testDeps(&firewall.FakeRunner{})
	d.newFetcher = archiveFetcher(archive)

	r := runCLI(t, d, "update", "--cache-dir", dir)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "imported 2") {
		t.Fatalf("stdout = %q, want imported 2", r.stdout)
	}
	assertCached(t, filepath.Join(dir, cache.FileName("CH", source.Family4)), "1.2.3.0/24\n")
	assertCached(t, filepath.Join(dir, cache.FileName("US", source.Family4)), "5.6.7.0/24\n")
}

func TestUpdateFiltered(t *testing.T) {
	archive := makeTarGz(t, map[string]string{
		"./ch.zone": "1.2.3.0/24\n",
		"./us.zone": "5.6.7.0/24\n",
	})
	dir := t.TempDir()
	d := testDeps(&firewall.FakeRunner{})
	d.newFetcher = archiveFetcher(archive)

	r := runCLI(t, d, "update", "CH", "--cache-dir", dir)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	assertCached(t, filepath.Join(dir, cache.FileName("CH", source.Family4)), "1.2.3.0/24\n")
	if _, err := os.Stat(filepath.Join(dir, cache.FileName("US", source.Family4))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("US zone stat err = %v, want not-exist", err)
	}
}

func TestUpdateDryRun(t *testing.T) {
	dir := t.TempDir()
	d := testDeps(&firewall.FakeRunner{})
	called := false
	d.newFetcher = func(string) cache.Fetcher {
		return func(context.Context, string) ([]byte, error) {
			called = true
			return nil, errors.New("fetch must not run during dry-run")
		}
	}

	r := runCLI(t, d, "update", "--dry-run", "--cache-dir", dir)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	if called {
		t.Fatal("fetcher was called during --dry-run")
	}
	if !strings.Contains(r.stdout, source.AllZonesV4URL) {
		t.Fatalf("stdout = %q, want the all-zones URL", r.stdout)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("cache dir has %d entries, want 0", len(entries))
	}
}

func TestUpdateV6PerCountry(t *testing.T) {
	dir := t.TempDir()
	d := testDeps(&firewall.FakeRunner{})
	d.newFetcher = func(string) cache.Fetcher {
		return func(_ context.Context, url string) ([]byte, error) {
			if url == source.PrimaryURL("CH", source.Family6) {
				return []byte("2001:db8::/32\n"), nil
			}
			return nil, errors.New("unexpected URL: " + url)
		}
	}

	r := runCLI(t, d, "update", "--v4=false", "--v6", "CH", "--cache-dir", dir)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", r.code, r.stderr)
	}
	assertCached(t, filepath.Join(dir, cache.FileName("CH", source.Family6)), "2001:db8::/32\n")
}

func TestUpdateV6RequiresCodes(t *testing.T) {
	d := testDeps(&firewall.FakeRunner{})
	r := runCLI(t, d, "update", "--v4=false", "--v6", "--cache-dir", t.TempDir())
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr=%q)", r.code, r.stderr)
	}
}

func TestUpdateV6DryRunRequiresCodes(t *testing.T) {
	d := testDeps(&firewall.FakeRunner{})
	r := runCLI(t, d, "update", "--v4=false", "--v6", "--dry-run", "--cache-dir", t.TempDir())
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr=%q)", r.code, r.stderr)
	}
}

func TestUpdateNoFamilies(t *testing.T) {
	d := testDeps(&firewall.FakeRunner{})
	r := runCLI(t, d, "update", "--v4=false", "--v6=false", "--cache-dir", t.TempDir())
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr=%q)", r.code, r.stderr)
	}
}

func TestUpdateInvalidCountry(t *testing.T) {
	d := testDeps(&firewall.FakeRunner{})
	r := runCLI(t, d, "update", "ZZ1", "--cache-dir", t.TempDir())
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr=%q)", r.code, r.stderr)
	}
}

func TestUpdateCountryMissingFromArchive(t *testing.T) {
	archive := makeTarGz(t, map[string]string{"./ch.zone": "1.2.3.0/24\n"})
	d := testDeps(&firewall.FakeRunner{})
	d.newFetcher = archiveFetcher(archive)

	r := runCLI(t, d, "update", "ZZ", "--cache-dir", t.TempDir())
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr=%q)", r.code, r.stderr)
	}
}

func assertCached(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cache %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
