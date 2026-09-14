# geo-iptables

`geo-iptables` loads per-country IP address ranges and applies them as an
`ipset` + `iptables` block list (or allow list). Country zones are downloaded
from [ipdeny.com](https://www.ipdeny.com/) with an
[ipverse/rir-ip](https://github.com/ipverse/rir-ip) fallback, cached on disk,
and installed into a dedicated `GEOBLOCK` chain.

- Block or allow traffic by ISO 3166-1 alpha-2 country code.
- One-shot bulk download of all IPv4 country zones.
- IPv4 and IPv6.
- Idempotent apply with atomic ipset swaps; `flush` removes everything.
- Cache-aware: reuses fresh zones and falls back to stale data when offline.
- `--dry-run` prints every `ipset`/`iptables` command without executing it.

## Requirements

- Linux with `iptables` (and `ip6tables` for `--v6`) and `ipset` installed.
- `root` privileges to change the firewall. `--dry-run` and `update` do not
  need root.
- Go 1.22+ to build from source. There are no third-party Go dependencies.

The binary compiles on other platforms, but only Linux can execute the firewall
commands; use `--dry-run` elsewhere.

## Build and install

```bash
go build -o geo-iptables ./cmd/geo-iptables
sudo install -m 0755 geo-iptables /usr/local/bin/geo-iptables
```

## Quick start

```bash
# 1. Cache all IPv4 country zones (single tarball download, no root needed).
geo-iptables update

# 2. Block Russia and China (IPv4 by default).
sudo geo-iptables block RU,CN

# 3. Inspect what is installed.
sudo geo-iptables status

# 4. Remove the chain, jump and ipsets.
sudo geo-iptables flush
```

## Commands

| Command | Description |
| --- | --- |
| `block <CC,...>` | Load the given countries' zones and add them to the block list. |
| `allow <CC,...>` | Allow only the given countries; all other source traffic is dropped. |
| `apply` | Apply a full desired state from `--allow` and/or `--block`. |
| `update [CC,...]` | Download country zones into the cache (all IPv4 zones by default). |
| `flush` | Remove the `INPUT` jump, the `GEOBLOCK` chain and the managed ipsets. |
| `status` | Show the state of the chain, the `INPUT` jump and the ipsets. |
| `version` | Print the version. |
| `help` | Print usage. |

Country codes are comma- or space-separated, case-insensitive, and must be two
letters (for example `CH` or `us`). Flags are conventionally written before the
country codes, but may be interspersed.

Exit codes: `0` success, `1` runtime or domain error (bad country code, network
failure, not root), `2` usage error (unknown command, missing arguments, bad
flag).

## Flags

Flags common to `block`, `allow` and `apply`:

| Flag | Default | Description |
| --- | --- | --- |
| `--v4` | `true` | Manage IPv4 rules. |
| `--v6` | `false` | Manage IPv6 rules. |
| `--ssh-exempt LIST` | | Comma-separated IP addresses or CIDR networks that always bypass the block list. |
| `--log` | `false` | Log dropped packets (rate-limited to 10/min). |
| `--dry-run` | `false` | Print commands instead of executing them. |
| `--cache-dir DIR` | user cache dir | Zone cache directory (`${XDG_CACHE_HOME:-$HOME/.cache}/geo-iptables`). |
| `--max-age DUR` | `24h` | Reuse cached zones younger than this; `0` always refetches. |
| `--refresh` | `false` | Force a refetch even when the cache is fresh. |

Additional flags:

- `apply`: `--allow LIST`, `--block LIST`.
- `update`: `--v4`, `--v6`, `--cache-dir`, `--dry-run`.
- `flush`: `--v4`, `--v6`, `--dry-run`.
- `status`: `--v4`, `--v6`.

At least one address family must be enabled.

## Examples

### Block countries on IPv4 and IPv6

```bash
sudo geo-iptables block RU,CN --v4 --v6
```

### Allowlist: only permit a few countries

```bash
sudo geo-iptables apply --allow CH,DE,AT
```

Everything from outside those countries (and not otherwise exempt) is dropped.

### Combine allow and block

```bash
sudo geo-iptables apply --allow CH,DE --block RU
```

The block list is evaluated before the allow list, so a source matching both is
dropped.

### Keep your own address reachable

```bash
sudo geo-iptables apply --allow CH --ssh-exempt 203.0.113.7,192.168.1.0/24
```

Exempt addresses and networks return before the block and allow-list rules, so
your admin IP is never dropped.

### Preview changes

```bash
sudo geo-iptables block RU --dry-run
```

### Refresh and cache control

```bash
geo-iptables update --refresh          # re-download everything now
geo-iptables update CH --v6            # cache only Switzerland IPv6
sudo geo-iptables block CH --max-age 1h
```

## Caching

- Default directory: `${XDG_CACHE_HOME:-$HOME/.cache}/geo-iptables`.
- One file per country and family, for example `CH-v4.zone` and `CH-v6.zone`.
- `--max-age` (default `24h`) controls when a cached zone is reused;
  `--refresh` forces a refetch; `--max-age 0` always refetches.
- Fresh cached zones avoid the network. If every source fails, the last cached
  copy is used with a warning; if nothing is cached, the command fails.

## How it works

`block`, `allow` and `apply` resolve each country to its zone, parse it into
prefixes, and install the result:

1. The countries are loaded from the cache or downloaded if stale.
2. Prefixes are loaded into ipsets. The contents of each set are replaced
   atomically using a temporary set and `ipset swap`, so there is never a
   window with an empty set.
3. The `GEOBLOCK` chain is created if needed, flushed, and rebuilt with the
   current rules. The chain is hooked into `INPUT` at position 1.

Managed ipsets, one per logical list and family:

- `geoip_allow4` / `geoip_allow6`
- `geoip_block4` / `geoip_block6`
- `geoip_ssh_exempt4` / `geoip_ssh_exempt6`

Rules are evaluated in this order:

1. Established/related connections return.
2. Loopback returns.
3. IPv6 NDP/RA/RS/NS (ICMPv6 133-136) returns.
4. DHCP returns (IPv4 UDP 67→68, IPv6 UDP 547→546).
5. `--ssh-exempt` addresses return.
6. Blocked countries are dropped (optionally logged).
7. Allowed countries return.
8. If an allow list is present, everything else is dropped; otherwise the
   chain returns and the host's normal policy applies.

Re-running `block`/`allow`/`apply` is idempotent and produces the same chain.
`flush` removes the `INPUT` jump, deletes the chain and destroys the ipsets.

## IPv4 and IPv6

- IPv4 zones are fetched per country, or in bulk: `update` downloads the
  [all-zones tarball](https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz)
  once and imports every country.
- ipdeny publishes no IPv6 all-zones tarball, so `update --v6` requires explicit
  country codes and fetches them individually.
- IPv6 always exempts NDP and DHCPv6 so the host keeps working.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `must be run as root` | Re-run with `sudo`, or use `--dry-run` to preview. |
| `ipset: command not found` / `iptables: ... not found` | Install the `ipset` and `iptables` packages. |
| Locked out after an allowlist | Reconnect on the console. Established connections return, and `--ssh-exempt` prevents this; `sudo geo-iptables flush` restores normal policy. |
| Zone download failures | The cached copy is used with a warning. Run `geo-iptables update` when back online. |
| `no IPv6 all-zones archive is available` | `update --v6` needs country codes, for example `update --v6 CH,US`. |

## Development

```bash
gofmt -l .
go vet ./...
go test ./...
```

## Project layout

```
cmd/geo-iptables/   CLI entry point
internal/app/       command parsing and orchestration
internal/cache/     zone download, disk cache, tarball import
internal/source/    zone URLs and zone parsing
internal/firewall/  ipset/iptables manager and command runner
internal/countries/ country-code parsing and validation
internal/version/   version string
```
