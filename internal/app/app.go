// Package app implements the geo-iptables command-line interface.
package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"geo-iptables/internal/cache"
	"geo-iptables/internal/countries"
	"geo-iptables/internal/firewall"
	"geo-iptables/internal/source"
	"geo-iptables/internal/version"
)

// deps carries the injectable dependencies used by run. A nil field falls back
// to the production implementation.
type deps struct {
	newFetcher func(userAgent string) cache.Fetcher // nil → cache.NewHTTPFetcher
	runner     firewall.Runner                      // nil → per --dry-run
	euid       func() int                           // nil → os.Geteuid
	now        func() time.Time                     // reserved; cache.Store has no exported clock hook
}

// Run executes the geo-iptables CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return run(ctx, args, stdout, stderr, deps{})
}

const usageText = `Usage:
  geo-iptables <command> [flags] [country codes...]

Commands:
  block <CC,...>    Load country zones and add their addresses to the block list.
  allow <CC,...>    Allow only the given countries; drop everything else.
  apply             Apply a full desired state (--allow, --block, --ssh-exempt).
  flush             Remove the INPUT jump, GEOBLOCK chain and managed ipsets.
  status            Show chain/jump/ipset state.
  update [CC,...]   Download and cache country zones (all IPv4 zones by default).
  version           Print the version.
  help              Show usage.

Country codes may be comma- or space-separated. Flags are conventionally
written before the positional country codes.

Common flags for block/allow/apply:
  --v4                 manage IPv4 rules (default true)
  --v6                 manage IPv6 rules (default false)
  --ssh-exempt LIST    comma-separated IP addresses exempt from blocking
  --log                log dropped packets
  --dry-run            print commands without executing them
  --cache-dir DIR      zone cache directory (default: user cache dir)
  --max-age DUR        maximum cache age before a refresh (default 24h)
  --refresh            force a cache refresh

apply additionally accepts:
  --allow LIST         comma-separated countries to allow
  --block LIST         comma-separated countries to block

update flags: --v4, --v6, --cache-dir, --dry-run
flush flags:  --v4, --v6, --dry-run
status flags: --v4, --v6
`

const usageHint = "Run 'geo-iptables help' for usage.\n"

// commonFlags holds the flags shared by block/allow/apply (and the subsets used
// by flush/status).
type commonFlags struct {
	v4        bool
	v6        bool
	sshExempt string
	log       bool
	dryRun    bool
	cacheDir  string
	maxAge    time.Duration
	refresh   bool
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	if d.newFetcher == nil {
		d.newFetcher = cache.NewHTTPFetcher
	}
	if d.euid == nil {
		d.euid = os.Geteuid
	}

	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "geo-iptables %s\n", version.Version)
		return 0
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "block", "allow":
		return runBlockAllow(ctx, cmd, rest, stdout, stderr, d)
	case "apply":
		return runApply(ctx, rest, stdout, stderr, d)
	case "flush":
		return runFlush(ctx, rest, stdout, stderr, d)
	case "status":
		return runStatus(ctx, rest, stdout, stderr, d)
	case "update":
		return runUpdate(ctx, rest, stdout, stderr, d)
	default:
		fmt.Fprintf(stderr, "geo-iptables: unknown command %q\n", cmd)
		fmt.Fprint(stderr, usageHint)
		return 2
	}
}

// parseFlags parses args with the flag set, tolerating flags interspersed with
// positional arguments (stdlib flag stops at the first non-flag token; we
// consume one positional and re-parse the remainder). It returns the
// positional arguments, an exit code and whether parsing is terminal.
func parseFlags(fs *flag.FlagSet, args []string) (positional []string, code int, done bool) {
	rest := args
	for {
		err := fs.Parse(rest)
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, 0, true
			}
			// The FlagSet has already written the parse error; add our hint.
			fmt.Fprint(fs.Output(), usageHint)
			return nil, 2, true
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, 0, false
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}

func addCommonFlags(fs *flag.FlagSet, cf *commonFlags) {
	fs.BoolVar(&cf.v4, "v4", true, "manage IPv4 rules")
	fs.BoolVar(&cf.v6, "v6", false, "manage IPv6 rules")
	fs.StringVar(&cf.sshExempt, "ssh-exempt", "", "comma-separated IP addresses exempt from blocking")
	fs.BoolVar(&cf.log, "log", false, "log dropped packets")
	fs.BoolVar(&cf.dryRun, "dry-run", false, "print commands without executing them")
	fs.StringVar(&cf.cacheDir, "cache-dir", cache.DefaultDir(), "zone cache directory")
	fs.DurationVar(&cf.maxAge, "max-age", 24*time.Hour, "maximum cache age before a refresh")
	fs.BoolVar(&cf.refresh, "refresh", false, "force a cache refresh")
}

func validateFamilies(cf *commonFlags, stderr io.Writer) bool {
	if cf.v4 || cf.v6 {
		return true
	}
	fmt.Fprintln(stderr, "geo-iptables: at least one of --v4 or --v6 must be enabled")
	fmt.Fprint(stderr, usageHint)
	return false
}

func checkRoot(dryRun bool, d deps, stderr io.Writer) bool {
	if dryRun || d.euid() == 0 {
		return true
	}
	fmt.Fprintln(stderr, "geo-iptables: must be run as root (try sudo, or use --dry-run)")
	return false
}

func runnerFor(d deps, dryRun bool, stdout io.Writer) firewall.Runner {
	if d.runner != nil {
		return d.runner
	}
	if dryRun {
		return firewall.DryRunner{Out: stdout}
	}
	return firewall.ExecRunner{}
}

// warnTo returns a Warn callback that prefixes messages for the CLI.
func warnTo(stderr io.Writer) func(string, ...any) {
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(stderr, "geo-iptables: warning: %s\n", msg)
	}
}

// parseSSHExempt parses a comma-separated list of plain IP addresses.
func parseSSHExempt(s string, stderr io.Writer) ([]netip.Addr, bool) {
	if strings.TrimSpace(s) == "" {
		return nil, true
	}
	var addrs []netip.Addr
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			fmt.Fprintf(stderr, "geo-iptables: invalid ssh-exempt address %q\n", part)
			return nil, false
		}
		addrs = append(addrs, a)
	}
	return addrs, true
}

// newStore builds a cache.Store from the parsed flags and dependencies.
func newStore(d deps, cf commonFlags, stderr io.Writer) *cache.Store {
	return &cache.Store{
		Dir:     cf.cacheDir,
		MaxAge:  cf.maxAge,
		Refresh: cf.refresh,
		Fetch:   d.newFetcher("geo-iptables/" + version.Version),
		Warn:    warnTo(stderr),
	}
}

// loadZones loads and parses the zones for every code/family pair, appending
// prefixes to per-family buckets. On failure it prints the error and reports
// exit code 1 via ok=false.
func loadZones(ctx context.Context, store *cache.Store, codes []string, cf commonFlags, stdout, stderr io.Writer) (p4, p6 []netip.Prefix, code int, ok bool) {
	for _, cc := range codes {
		if cf.v4 {
			ps, err := loadOne(ctx, store, cc, source.Family4, stdout, stderr)
			if err != nil {
				fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
				return nil, nil, 1, false
			}
			p4 = append(p4, ps...)
		}
		if cf.v6 {
			ps, err := loadOne(ctx, store, cc, source.Family6, stdout, stderr)
			if err != nil {
				fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
				return nil, nil, 1, false
			}
			p6 = append(p6, ps...)
		}
	}
	return p4, p6, 0, true
}

func loadOne(ctx context.Context, store *cache.Store, cc string, family int, stdout, stderr io.Writer) ([]netip.Prefix, error) {
	body, err := store.Load(ctx, cc, family)
	if err != nil {
		return nil, err
	}
	res, err := source.Parse(bytes.NewReader(body), family)
	if err != nil {
		return nil, err
	}
	tag := "v4"
	if family == source.Family6 {
		tag = "v6"
	}
	fmt.Fprintf(stdout, "%s %s: %d prefixes\n", cc, tag, len(res.Prefixes))
	if res.Invalid > 0 {
		fmt.Fprintf(stderr, "geo-iptables: warning: %s %s: skipped %d invalid lines\n", cc, tag, res.Invalid)
	}
	if res.Duplicates > 0 {
		fmt.Fprintf(stderr, "geo-iptables: warning: %s %s: skipped %d duplicate lines\n", cc, tag, res.Duplicates)
	}
	return res.Prefixes, nil
}

func runBlockAllow(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	addCommonFlags(fs, &cf)

	positional, code, done := parseFlags(fs, args)
	if done {
		return code
	}
	if !validateFamilies(&cf, stderr) {
		return 2
	}

	codes, err := countries.Parse(strings.Join(positional, ","))
	if err != nil {
		fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
		return 1
	}
	if len(codes) == 0 {
		fmt.Fprintf(stderr, "geo-iptables: %s requires at least one country code\n", cmd)
		fmt.Fprint(stderr, usageHint)
		return 2
	}

	ssh, ok := parseSSHExempt(cf.sshExempt, stderr)
	if !ok {
		return 1
	}
	if !checkRoot(cf.dryRun, d, stderr) {
		return 1
	}

	p4, p6, code, ok := loadZones(ctx, newStore(d, cf, stderr), codes, cf, stdout, stderr)
	if !ok {
		return code
	}

	all := append(append([]netip.Prefix(nil), p4...), p6...)
	req := firewall.Request{
		SSHExempt: ssh,
		IPv4:      cf.v4,
		IPv6:      cf.v6,
		Log:       cf.log,
	}
	if cmd == "block" {
		req.Block = all
	} else {
		req.Allow = all
	}

	mgr := &firewall.Manager{Runner: runnerFor(d, cf.dryRun, stdout), Warn: warnTo(stderr)}
	if err := mgr.Apply(ctx, req); err != nil {
		fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
		return 1
	}
	if !cf.dryRun {
		fmt.Fprintln(stdout, "applied")
	}
	return 0
}

func runApply(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	addCommonFlags(fs, &cf)
	allowList := fs.String("allow", "", "comma-separated countries to allow")
	blockList := fs.String("block", "", "comma-separated countries to block")

	_, code, done := parseFlags(fs, args)
	if done {
		return code
	}
	if !validateFamilies(&cf, stderr) {
		return 2
	}
	if strings.TrimSpace(*allowList) == "" && strings.TrimSpace(*blockList) == "" {
		fmt.Fprintln(stderr, "geo-iptables: apply requires at least one of --allow or --block")
		fmt.Fprint(stderr, usageHint)
		return 2
	}

	allowCodes, err := countries.Parse(*allowList)
	if err != nil {
		fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
		return 1
	}
	blockCodes, err := countries.Parse(*blockList)
	if err != nil {
		fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
		return 1
	}

	ssh, ok := parseSSHExempt(cf.sshExempt, stderr)
	if !ok {
		return 1
	}
	if !checkRoot(cf.dryRun, d, stderr) {
		return 1
	}

	store := newStore(d, cf, stderr)
	allow4, allow6, code, ok := loadZones(ctx, store, allowCodes, cf, stdout, stderr)
	if !ok {
		return code
	}
	block4, block6, code, ok := loadZones(ctx, store, blockCodes, cf, stdout, stderr)
	if !ok {
		return code
	}

	req := firewall.Request{
		Allow:     append(append([]netip.Prefix(nil), allow4...), allow6...),
		Block:     append(append([]netip.Prefix(nil), block4...), block6...),
		SSHExempt: ssh,
		IPv4:      cf.v4,
		IPv6:      cf.v6,
		Log:       cf.log,
	}
	mgr := &firewall.Manager{Runner: runnerFor(d, cf.dryRun, stdout), Warn: warnTo(stderr)}
	if err := mgr.Apply(ctx, req); err != nil {
		fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
		return 1
	}
	if !cf.dryRun {
		fmt.Fprintln(stdout, "applied")
	}
	return 0
}

func runFlush(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("flush", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	fs.BoolVar(&cf.v4, "v4", true, "manage IPv4 rules")
	fs.BoolVar(&cf.v6, "v6", false, "manage IPv6 rules")
	fs.BoolVar(&cf.dryRun, "dry-run", false, "print commands without executing them")

	_, code, done := parseFlags(fs, args)
	if done {
		return code
	}
	if !validateFamilies(&cf, stderr) {
		return 2
	}
	if !checkRoot(cf.dryRun, d, stderr) {
		return 1
	}

	mgr := &firewall.Manager{Runner: runnerFor(d, cf.dryRun, stdout), Warn: warnTo(stderr)}
	if err := mgr.Flush(ctx, cf.v4, cf.v6); err != nil {
		fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
		return 1
	}
	return 0
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	fs.BoolVar(&cf.v4, "v4", true, "show IPv4 state")
	fs.BoolVar(&cf.v6, "v6", false, "show IPv6 state")

	_, code, done := parseFlags(fs, args)
	if done {
		return code
	}
	if !validateFamilies(&cf, stderr) {
		return 2
	}
	if !checkRoot(false, d, stderr) {
		return 1
	}

	mgr := &firewall.Manager{Runner: runnerFor(d, false, stdout), Warn: warnTo(stderr)}
	printStatus(stdout, mgr.Inspect(ctx, cf.v4, cf.v6))
	return 0
}

func runUpdate(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	fs.BoolVar(&cf.v4, "v4", true, "cache IPv4 zones")
	fs.BoolVar(&cf.v6, "v6", false, "cache IPv6 zones")
	fs.BoolVar(&cf.dryRun, "dry-run", false, "print the plan without downloading")
	fs.StringVar(&cf.cacheDir, "cache-dir", cache.DefaultDir(), "zone cache directory")

	positional, code, done := parseFlags(fs, args)
	if done {
		return code
	}
	if !validateFamilies(&cf, stderr) {
		return 2
	}
	codes, err := countries.Parse(strings.Join(positional, ","))
	if err != nil {
		fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
		return 1
	}
	// There is no IPv6 all-zones archive, so v6 always needs explicit codes.
	// Validate up front so --dry-run predicts the real run exactly.
	if cf.v6 && len(codes) == 0 {
		fmt.Fprintln(stderr, "geo-iptables: no IPv6 all-zones archive is available; list country codes for per-country downloads")
		return 1
	}

	if cf.dryRun {
		if cf.v4 {
			if len(codes) == 0 {
				fmt.Fprintf(stdout, "would import all IPv4 zones from %s\n", source.AllZonesV4URL)
			} else {
				fmt.Fprintf(stdout, "would import %s from %s\n", strings.Join(codes, ", "), source.AllZonesV4URL)
			}
		}
		if cf.v6 {
			fmt.Fprintf(stdout, "would fetch %d IPv6 country zones\n", len(codes))
		}
		return 0
	}

	store := &cache.Store{
		Dir:     cf.cacheDir,
		MaxAge:  24 * time.Hour,
		Refresh: true,
		Fetch:   d.newFetcher("geo-iptables/" + version.Version),
		Warn:    warnTo(stderr),
	}

	if cf.v4 {
		res, err := store.ImportArchive(ctx, source.AllZonesV4URL, source.Family4, codes)
		if err != nil {
			fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "imported %d IPv4 zones (%d bytes)\n", len(res.Countries), res.Bytes)
		if len(codes) > 0 {
			found := make(map[string]bool, len(res.Countries))
			for _, cc := range res.Countries {
				found[cc] = true
			}
			missing := 0
			for _, cc := range codes {
				if !found[cc] {
					fmt.Fprintf(stderr, "geo-iptables: warning: country %s not found in IPv4 archive\n", cc)
					missing++
				}
			}
			if missing == len(codes) {
				fmt.Fprintln(stderr, "geo-iptables: none of the requested IPv4 countries were found in the archive")
				return 1
			}
		}
	}

	if cf.v6 {
		for _, cc := range codes {
			if _, err := store.Load(ctx, cc, source.Family6); err != nil {
				fmt.Fprintf(stderr, "geo-iptables: %v\n", err)
				return 1
			}
			fmt.Fprintf(stdout, "%s v6: cached\n", cc)
		}
	}
	return 0
}

func printStatus(w io.Writer, sts []firewall.FamilyStatus) {
	for _, st := range sts {
		fmt.Fprintf(w, "IPv%d\n", st.Family)
		fmt.Fprintf(w, "  chain %s: %s\n", firewall.ChainName, presentWord(st.Chain))
		fmt.Fprintf(w, "  INPUT jump: %s\n", presentWord(st.Jump))
		for _, s := range st.Sets {
			fmt.Fprintf(w, "  ipset %s: %s\n", s.Name, setWord(s))
		}
	}
}

func presentWord(b bool) string {
	if b {
		return "present"
	}
	return "not present"
}

func setWord(s firewall.SetStatus) string {
	if !s.Present {
		return "not present"
	}
	if s.Entries >= 0 {
		return fmt.Sprintf("%d entries", s.Entries)
	}
	return "present"
}
