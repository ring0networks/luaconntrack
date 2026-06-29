# luaconntrack

Lua binding for [libnetfilter_conntrack](https://netfilter.org/projects/libnetfilter_conntrack/). Reads conntrack entries (tuple, mark, byte/packet counters) from Lua.

Netlink is hidden behind the high-level libnetfilter_conntrack API, the same way
the [`nftables`](https://github.com/ring0networks/luanftables) binding hides it
for libnftables.

## Build

Requires `libnetfilter-conntrack-dev` and Lua (>= 5.4) headers.

```
sudo apt install libnetfilter-conntrack-dev lua5.4 liblua5.4-dev
make
sudo make install
```

The build auto-detects the Lua version via `pkg-config` (prefers 5.5, falls back to 5.4).
To override: `make LUA_VERSION=5.4`.

## Usage

```lua
local conntrack = require("conntrack")
local ct <close> = conntrack.open()

-- list every conntrack entry (all families by default)
for _, flow in ipairs(ct:list()) do
    print(flow.saddr, flow.sport, flow.daddr, flow.dport, flow.mark)
end

-- list only entries whose mark matches a value under a mask (kernel-side filter)
local flows = ct:list{ mark = 0x02000000, mask = 0x02000000 }
```

Each flow table holds:

| field | type | notes |
|-------|------|-------|
| `saddr`, `daddr` | string | original-direction source/dest, dotted IPv4 or colon IPv6 |
| `sport`, `dport` | integer | host byte order |
| `proto` | integer | IP protocol number; compare with `conntrack.IPPROTO_TCP`/`UDP`/`ICMP`/`ICMPV6` (any value can appear) |
| `family` | integer | address family; `conntrack.AF_INET` (2) or `conntrack.AF_INET6` (10) |
| `mark` | integer | raw `ct->mark` (decode bit layout in the caller) |
| `orig_bytes`, `repl_bytes` | integer | per-direction byte counters |
| `orig_packets`, `repl_packets` | integer | per-direction packet counters |

Counters are zero unless the kernel has `CONFIG_NF_CONNTRACK_ACCT`
(`net.netfilter.nf_conntrack_acct=1`).

## Constants

Exported as module fields, so callers avoid raw numbers:

- `conntrack.AF_UNSPEC` / `conntrack.AF_INET` / `conntrack.AF_INET6` — the
  `family` option and field.
- `conntrack.IPPROTO_TCP` / `IPPROTO_UDP` / `IPPROTO_ICMP` / `IPPROTO_ICMPV6` —
  the `proto` field. `proto` is the raw IP protocol number, so other values can
  appear; these are the common ones.

## [API](https://ring0networks.github.io/luaconntrack/)

| Method | Description |
|--------|-------------|
| `conntrack.open()` | Open a conntrack handle |
| `ct:list([opts])` | List entries; `opts.mark`/`opts.mask`/`opts.family` |
| `ct:close()` | Free the handle (idempotent; also via `<close>` / `__gc`) |

## Requirements

- Lua >= 5.4
- libnetfilter_conntrack (runtime)
- libnetfilter-conntrack-dev (build)
- Root or `CAP_NET_ADMIN` to read conntrack

## License

MIT
