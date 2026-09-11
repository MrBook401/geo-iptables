package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	setAllow     = "allow"
	setBlock     = "block"
	setSSHExempt = "ssh_exempt"
)

// family bundles the per-address-family parameters.
type family struct {
	Num    int    // 4 or 6
	IPT    string // iptables or ip6tables
	Kernel string // inet or inet6
}

func familyFor(num int) family {
	if num == 6 {
		return family{Num: 6, IPT: "ip6tables", Kernel: "inet6"}
	}
	return family{Num: 4, IPT: "iptables", Kernel: "inet"}
}

// SetName returns the ipset name for a logical set and family, e.g.
// geoip_allow4 or geoip_ssh_exempt6.
func SetName(kind string, num int) string {
	return fmt.Sprintf("geoip_%s%d", kind, num)
}

// Request describes a desired firewall state.
type Request struct {
	Allow     []netip.Prefix
	Block     []netip.Prefix
	SSHExempt []netip.Addr
	IPv4      bool
	IPv6      bool
	Log       bool
}

// Manager applies requests through a Runner.
type Manager struct {
	Runner Runner
	Warn   func(format string, args ...any)
}

func (m *Manager) warn(format string, args ...any) {
	if m.Warn != nil {
		m.Warn(format, args...)
	}
}

func (m *Manager) isDryRun() bool {
	if d, ok := m.Runner.(interface{ DryRun() bool }); ok {
		return d.DryRun()
	}
	return false
}

// Apply installs ipsets, the GEOBLOCK chain and the INPUT jump for each
// enabled family. It is idempotent: re-running produces the same chain.
func (m *Manager) Apply(ctx context.Context, req Request) error {
	if req.IPv4 {
		if err := m.applyFamily(ctx, familyFor(4), req); err != nil {
			return err
		}
	}
	if req.IPv6 {
		if err := m.applyFamily(ctx, familyFor(6), req); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) applyFamily(ctx context.Context, fam family, req Request) error {
	allow := prefixesFor(req.Allow, fam.Num)
	block := prefixesFor(req.Block, fam.Num)
	ssh := addrsFor(req.SSHExempt, fam.Num)

	if len(allow) > 0 {
		if err := m.loadSet(ctx, SetName(setAllow, fam.Num), fam.Kernel, allow); err != nil {
			return err
		}
	}
	if len(block) > 0 {
		if err := m.loadSet(ctx, SetName(setBlock, fam.Num), fam.Kernel, block); err != nil {
			return err
		}
	}
	if len(ssh) > 0 {
		prefixes := make([]netip.Prefix, 0, len(ssh))
		for _, a := range ssh {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
		if err := m.loadSet(ctx, SetName(setSSHExempt, fam.Num), fam.Kernel, prefixes); err != nil {
			return err
		}
	}

	// Ensure the chain exists, then flush it. Tolerate "already exists".
	if _, err := m.Runner.Run(ctx, fam.IPT, []string{"-N", ChainName}, ""); err != nil {
		_ = err
	}
	if _, err := m.Runner.Run(ctx, fam.IPT, []string{"-F", ChainName}, ""); err != nil {
		return fmt.Errorf("%s -F %s: %w", fam.IPT, ChainName, err)
	}

	for _, rule := range buildRules(fam, req) {
		args := append([]string{"-A", ChainName}, rule...)
		if _, err := m.Runner.Run(ctx, fam.IPT, args, ""); err != nil {
			return fmt.Errorf("%s -A %s: %w", fam.IPT, ChainName, err)
		}
	}

	return m.ensureJump(ctx, fam)
}

// loadSet atomically replaces the contents of name with prefixes using a
// temporary set and ipset swap.
func (m *Manager) loadSet(ctx context.Context, name, kernel string, prefixes []netip.Prefix) error {
	tmp := name + "_tmp"

	create := func(set string) []string {
		return []string{"create", set, "hash:net", "family", kernel, "maxelem", "1000000", "hashsize", "1024", "-exist"}
	}

	if _, err := m.Runner.Run(ctx, "ipset", create(name), ""); err != nil {
		return fmt.Errorf("ipset create %s: %w", name, err)
	}
	if _, err := m.Runner.Run(ctx, "ipset", create(tmp), ""); err != nil {
		return fmt.Errorf("ipset create %s: %w", tmp, err)
	}
	if _, err := m.Runner.Run(ctx, "ipset", []string{"flush", tmp}, ""); err != nil {
		return fmt.Errorf("ipset flush %s: %w", tmp, err)
	}

	if len(prefixes) > 0 {
		var b strings.Builder
		for _, p := range prefixes {
			fmt.Fprintf(&b, "add %s %s -exist\n", tmp, p.String())
		}
		if _, err := m.Runner.Run(ctx, "ipset", []string{"restore", "-exist"}, b.String()); err != nil {
			return fmt.Errorf("ipset restore into %s: %w", tmp, err)
		}
	}

	if _, err := m.Runner.Run(ctx, "ipset", []string{"swap", tmp, name}, ""); err != nil {
		return fmt.Errorf("ipset swap %s %s: %w", tmp, name, err)
	}
	if _, err := m.Runner.Run(ctx, "ipset", []string{"destroy", tmp}, ""); err != nil {
		m.warn("ipset destroy %s failed: %v", tmp, err)
	}

	if !m.isDryRun() {
		if err := m.verifySet(ctx, name, len(prefixes)); err != nil {
			m.warn("%v", err)
		}
	}
	return nil
}

func (m *Manager) verifySet(ctx context.Context, name string, expected int) error {
	out, err := m.Runner.Run(ctx, "ipset", []string{"list", name, "-terse"}, "")
	if err != nil {
		return fmt.Errorf("verify ipset %s: %w", name, err)
	}
	if got := parseEntryCount(out); got >= 0 && got != expected {
		return fmt.Errorf("ipset %s has %d entries, expected %d (possible maxelem overflow)", name, got, expected)
	}
	return nil
}

func (m *Manager) ensureJump(ctx context.Context, fam family) error {
	if m.isDryRun() {
		_, err := m.Runner.Run(ctx, fam.IPT, []string{"-I", "INPUT", "1", "-j", ChainName}, "")
		return err
	}
	if _, err := m.Runner.Run(ctx, fam.IPT, []string{"-C", "INPUT", "-j", ChainName}, ""); err == nil {
		return nil
	}
	if _, err := m.Runner.Run(ctx, fam.IPT, []string{"-I", "INPUT", "1", "-j", ChainName}, ""); err != nil {
		return fmt.Errorf("%s -I INPUT -j %s: %w", fam.IPT, ChainName, err)
	}
	return nil
}

// buildRules returns the GEOBLOCK rules in their required order.
func buildRules(fam family, req Request) [][]string {
	var rules [][]string

	// 1. Established/related traffic.
	rules = append(rules, []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"})
	// 2. Loopback.
	rules = append(rules, []string{"-i", "lo", "-j", "RETURN"})
	// 3. IPv6 NDP/RA/RS/NS/NA (mandatory).
	if fam.Num == 6 {
		for _, t := range []string{"133", "134", "135", "136"} {
			rules = append(rules, []string{"-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "RETURN"})
		}
	}
	// 4. DHCP.
	if fam.Num == 6 {
		rules = append(rules, []string{"-p", "udp", "--sport", "547", "--dport", "546", "-j", "RETURN"})
	} else {
		rules = append(rules, []string{"-p", "udp", "--sport", "67", "--dport", "68", "-j", "RETURN"})
	}
	// 5. SSH exemption.
	if len(addrsFor(req.SSHExempt, fam.Num)) > 0 {
		rules = append(rules, []string{"-m", "set", "--match-set", SetName(setSSHExempt, fam.Num), "src", "-j", "RETURN"})
	}
	// 6. Blocked countries take precedence.
	if len(prefixesFor(req.Block, fam.Num)) > 0 {
		if req.Log {
			rules = append(rules, logRule())
		}
		rules = append(rules, []string{"-m", "set", "--match-set", SetName(setBlock, fam.Num), "src", "-j", "DROP"})
	}
	// 7. Allowed countries.
	if len(prefixesFor(req.Allow, fam.Num)) > 0 {
		rules = append(rules, []string{"-m", "set", "--match-set", SetName(setAllow, fam.Num), "src", "-j", "RETURN"})
	}
	// 8. Final policy.
	if len(prefixesFor(req.Allow, fam.Num)) > 0 {
		if req.Log {
			rules = append(rules, logRule())
		}
		rules = append(rules, []string{"-j", "DROP"})
	} else {
		rules = append(rules, []string{"-j", "RETURN"})
	}
	return rules
}

func logRule() []string {
	return []string{"-m", "limit", "--limit", "10/min", "-j", "LOG", "--log-prefix", "geoip-drop: "}
}

func prefixesFor(ps []netip.Prefix, num int) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range ps {
		if num == 4 && p.Addr().Is4() {
			out = append(out, p)
		}
		if num == 6 && p.Addr().Is6() {
			out = append(out, p)
		}
	}
	return out
}

func addrsFor(as []netip.Addr, num int) []netip.Addr {
	var out []netip.Addr
	for _, a := range as {
		if num == 4 && a.Is4() {
			out = append(out, a)
		}
		if num == 6 && a.Is6() {
			out = append(out, a)
		}
	}
	return out
}

func parseEntryCount(out string) int {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Number of entries:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "Number of entries:"))
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return -1
}

// Flush removes the INPUT jump, deletes the GEOBLOCK chain and destroys our
// ipsets for the enabled families. It is idempotent and ignores missing state.
func (m *Manager) Flush(ctx context.Context, ipv4, ipv6 bool) error {
	fams := []family{}
	if ipv4 {
		fams = append(fams, familyFor(4))
	}
	if ipv6 {
		fams = append(fams, familyFor(6))
	}
	for _, fam := range fams {
		m.Runner.Run(ctx, fam.IPT, []string{"-D", "INPUT", "-j", ChainName}, "")
		m.Runner.Run(ctx, fam.IPT, []string{"-F", ChainName}, "")
		m.Runner.Run(ctx, fam.IPT, []string{"-X", ChainName}, "")
		for _, kind := range []string{setAllow, setBlock, setSSHExempt} {
			name := SetName(kind, fam.Num)
			m.Runner.Run(ctx, "ipset", []string{"destroy", name}, "")
			m.Runner.Run(ctx, "ipset", []string{"destroy", name + "_tmp"}, "")
		}
	}
	return nil
}

// SetStatus reports one ipset's state.
type SetStatus struct {
	Name    string
	Present bool
	Entries int
}

// FamilyStatus reports the firewall state for one address family.
type FamilyStatus struct {
	Family int
	Chain  bool
	Jump   bool
	Sets   []SetStatus
}

// Inspect queries the current firewall state for the enabled families.
func (m *Manager) Inspect(ctx context.Context, ipv4, ipv6 bool) []FamilyStatus {
	var out []FamilyStatus
	fams := []family{}
	if ipv4 {
		fams = append(fams, familyFor(4))
	}
	if ipv6 {
		fams = append(fams, familyFor(6))
	}
	for _, fam := range fams {
		st := FamilyStatus{Family: fam.Num}
		if _, err := m.Runner.Run(ctx, fam.IPT, []string{"-S", ChainName}, ""); err == nil {
			st.Chain = true
		}
		if _, err := m.Runner.Run(ctx, fam.IPT, []string{"-C", "INPUT", "-j", ChainName}, ""); err == nil {
			st.Jump = true
		}
		for _, kind := range []string{setAllow, setBlock, setSSHExempt} {
			name := SetName(kind, fam.Num)
			ss := SetStatus{Name: name, Entries: -1}
			if outStr, err := m.Runner.Run(ctx, "ipset", []string{"list", name, "-terse"}, ""); err == nil {
				ss.Present = true
				ss.Entries = parseEntryCount(outStr)
			}
			st.Sets = append(st.Sets, ss)
		}
		out = append(out, st)
	}
	return out
}
