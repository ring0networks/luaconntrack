-- Read conntrack entries from Lua. Needs root / CAP_NET_ADMIN.
local conntrack = require("conntrack")
local ct <close> = conntrack.open()

-- every conntrack entry: tuple, protocol, mark, per-direction byte counters
for _, f in ipairs(ct:list()) do
	print(string.format("%s:%d -> %s:%d  proto=%d mark=0x%08x  bytes=%d/%d",
		f.saddr, f.sport, f.daddr, f.dport, f.proto, f.mark, f.orig_bytes, f.repl_bytes))
end

-- only entries whose mark matches a value under a mask (filtered in the kernel)
local marked = ct:list{ mark = 0x02000000, mask = 0x02000000 }
print(("\n%d marked flow(s)"):format(#marked))

