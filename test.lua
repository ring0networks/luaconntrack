--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT
--
-- Smoke test for the conntrack binding. Needs root / CAP_NET_ADMIN. It asserts
-- the API contract over whatever the live conntrack table holds, so the data
-- tests pass vacuously (never wrongly) on an empty table.
--   sudo lua5.4 test.lua
package.cpath = "./?.so;" .. package.cpath

local conntrack = require("conntrack")

local function test(name, fn)
	local ok, err = pcall(fn)
	if ok then
		print(string.format("  PASS  %s", name))
	else
		print(string.format("  FAIL  %s: %s", name, err))
		os.exit(1)
	end
end

-- test: open returns a usable handle
test("open returns a handle", function()
	local ct <close> = conntrack.open()
	assert(ct ~= nil, "open returned nil")
end)

-- test: list returns an array of well-formed flow tables
test("list returns well-formed flows", function()
	local ct <close> = conntrack.open()
	local flows = ct:list()
	assert(type(flows) == "table", "list must return a table")
	for _, f in ipairs(flows) do
		assert(type(f.sport) == "number" and type(f.dport) == "number"
			and type(f.proto) == "number" and type(f.family) == "number"
			and type(f.mark) == "number"
			and type(f.orig_bytes) == "number" and type(f.repl_bytes) == "number"
			and type(f.orig_packets) == "number" and type(f.repl_packets) == "number",
			"flow is missing a scalar field")
		assert(f.saddr == nil or type(f.saddr) == "string", "saddr must be string or nil")
		assert(f.daddr == nil or type(f.daddr) == "string", "daddr must be string or nil")
	end
end)

-- test: the kernel-side mark filter returns only matching entries
test("mark filter returns only matching entries", function()
	local ct <close> = conntrack.open()
	local val, mask = 0x02000000, 0x02000000
	for _, f in ipairs(ct:list{ mark = val, mask = mask }) do
		assert((f.mark & mask) == val, "filtered flow does not match the mark")
	end
end)

-- test: close is idempotent
test("close is idempotent", function()
	local ct = conntrack.open()
	ct:close()
	ct:close()
end)

-- test: use after close errors
test("use after close errors", function()
	local ct = conntrack.open()
	ct:close()
	local ok, err = pcall(ct.list, ct)
	assert(not ok, "expected error after close")
	assert(tostring(err):find("closed", 1, true), "error should mention the closed handle")
end)

-- test: constants exported with their canonical values
test("constants exported", function()
	assert(conntrack.AF_UNSPEC == 0 and conntrack.AF_INET == 2
		and conntrack.AF_INET6 == 10, "address-family constants missing")
	assert(conntrack.IPPROTO_TCP == 6 and conntrack.IPPROTO_UDP == 17
		and conntrack.IPPROTO_ICMP == 1 and conntrack.IPPROTO_ICMPV6 == 58,
		"protocol constants missing")
end)

print("OK")

