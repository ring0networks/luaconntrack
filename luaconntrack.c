/*
 * SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
 * SPDX-License-Identifier: MIT
 */

/***
 * Lua binding for libnetfilter_conntrack.
 * Reads conntrack entries (tuple, mark, byte/packet counters) so a userspace
 * process can surface per-flow accounting. Thin wrapper over the high-level
 * libnetfilter_conntrack API; netlink is hidden, the same way the `nftables`
 * binding hides it for libnftables.
 * Exports the address-family (`AF_UNSPEC`/`AF_INET`/`AF_INET6`) and common
 * L4-protocol (`IPPROTO_TCP`/`IPPROTO_UDP`/`IPPROTO_ICMP`/`IPPROTO_ICMPV6`)
 * constants as module fields, so callers avoid raw numbers.
 * @module conntrack
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <lua.h>
#include <lauxlib.h>

#define LUACT_HANDLE	"conntrack.handle"

#define LUACT_ID(v)	(v)

/* Single source of truth for the scalar fields exposed as Lua integers: it drives
 * the record layout, the read from the entry, and the push to Lua. Columns:
 * field name, nfct getter width, attribute, value transform (ntohs for ports). */
#define LUACT_SCALARS(_)					\
	_(family,       u8,  ATTR_ORIG_L3PROTO,        LUACT_ID)	\
	_(proto,        u8,  ATTR_ORIG_L4PROTO,         LUACT_ID)	\
	_(sport,        u16, ATTR_ORIG_PORT_SRC,        ntohs)	\
	_(dport,        u16, ATTR_ORIG_PORT_DST,        ntohs)	\
	_(mark,         u32, ATTR_MARK,                 LUACT_ID)	\
	_(orig_bytes,   u64, ATTR_ORIG_COUNTER_BYTES,   LUACT_ID)	\
	_(repl_bytes,   u64, ATTR_REPL_COUNTER_BYTES,   LUACT_ID)	\
	_(orig_packets, u64, ATTR_ORIG_COUNTER_PACKETS, LUACT_ID)	\
	_(repl_packets, u64, ATTR_REPL_COUNTER_PACKETS, LUACT_ID)

typedef struct {
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
#define LUACT_FIELD(name, getter, attr, xform)	lua_Integer name;
	LUACT_SCALARS(LUACT_FIELD)
#undef LUACT_FIELD
} luact_flow;

typedef struct {
	luact_flow *flows;
	size_t n;
	size_t cap;
	int oom;
} luact_collect;

static struct nfct_handle *luact_check(lua_State *L, int ix)
{
	struct nfct_handle **ud = (struct nfct_handle **)luaL_checkudata(L, ix, LUACT_HANDLE);
	luaL_argcheck(L, *ud != NULL, ix, "conntrack handle already closed");
	return *ud;
}

static void luact_format_addr(char *buf, size_t len, int family, const void *addr)
{
	buf[0] = '\0';
	if (addr != NULL)
		inet_ntop(family, addr, buf, len);
}

/* Copy one entry into a C record. No Lua here: this runs inside nfct_query()'s
 * callback, where a Lua error would longjmp past the library's cleanup. */
static void luact_collect_flow(luact_flow *f, struct nf_conntrack *ct)
{
	f->src[0] = '\0';
	f->dst[0] = '\0';

	switch (nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO)) {
	case AF_INET: {
		uint32_t src = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
		uint32_t dst = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
		luact_format_addr(f->src, sizeof(f->src), AF_INET, &src);
		luact_format_addr(f->dst, sizeof(f->dst), AF_INET, &dst);
		break;
	}
	case AF_INET6:
		luact_format_addr(f->src, sizeof(f->src), AF_INET6, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC));
		luact_format_addr(f->dst, sizeof(f->dst), AF_INET6, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST));
		break;
	}

#define LUACT_FIELD(name, getter, attr, xform)	f->name = (lua_Integer)xform(nfct_get_attr_##getter(ct, attr));
	LUACT_SCALARS(LUACT_FIELD)
#undef LUACT_FIELD
}

static int luact_collect_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
	luact_collect *c = (luact_collect *)data;

	(void)type;

	if (c->n == c->cap) {
		size_t cap = c->cap ? c->cap * 2 : 64;
		if (cap > SIZE_MAX / sizeof(luact_flow)) {
			c->oom = 1;
			return NFCT_CB_STOP;
		}
		luact_flow *grown = (luact_flow *)realloc(c->flows, cap * sizeof(*grown));
		if (grown == NULL) {
			c->oom = 1;
			return NFCT_CB_STOP;
		}
		c->flows = grown;
		c->cap = cap;
	}

	luact_collect_flow(&c->flows[c->n++], ct);
	return NFCT_CB_CONTINUE;
}

static void luact_setfield_int(lua_State *L, const char *key, lua_Integer value)
{
	lua_pushinteger(L, value);
	lua_setfield(L, -2, key);
}

static void luact_setfield_addr(lua_State *L, const char *key, const char *addr)
{
	if (addr[0] != '\0')
		lua_pushstring(L, addr);
	else
		lua_pushnil(L);
	lua_setfield(L, -2, key);
}

/* Build the Lua array, after nfct_query() returned: a Lua error is safe here. */
static void luact_build(lua_State *L, const luact_collect *c)
{
	luaL_checkstack(L, 4, "conntrack list");
	lua_createtable(L, (int)c->n, 0);

	for (size_t i = 0; i < c->n; i++) {
		const luact_flow *f = &c->flows[i];

		lua_createtable(L, 0, 11);
		luact_setfield_addr(L, "saddr", f->src);
		luact_setfield_addr(L, "daddr", f->dst);
#define LUACT_FIELD(name, getter, attr, xform)	luact_setfield_int(L, #name, f->name);
		LUACT_SCALARS(LUACT_FIELD)
#undef LUACT_FIELD
		lua_rawseti(L, -2, (lua_Integer)(i + 1));
	}
}

/***
 * Open a conntrack handle.
 * @function open
 * @treturn handle conntrack handle (supports `<close>`)
 * @raise Error if the netlink handle cannot be opened.
 * @usage
 * local conntrack = require("conntrack")
 * local ct <close> = conntrack.open()
 */
static int luact_open(lua_State *L)
{
	struct nfct_handle *h = nfct_open(CONNTRACK, 0);
	if (h == NULL)
		return luaL_error(L, "nfct_open failed: %s", strerror(errno));

	struct nfct_handle **ud = (struct nfct_handle **)lua_newuserdatauv(L, sizeof(*ud), 0);
	*ud = h;
	luaL_setmetatable(L, LUACT_HANDLE);
	return 1;
}

/* Read the optional opts table: mark/mask filter and address family. */
static void luact_read_opts(lua_State *L, int idx, uint8_t *family,
	uint32_t *mark, uint32_t *mask, int *have_mark)
{
	*family = AF_UNSPEC;
	*mark = 0;
	*mask = 0;
	*have_mark = 0;

	if (lua_isnoneornil(L, idx))
		return;

	luaL_checktype(L, idx, LUA_TTABLE);
	if (lua_getfield(L, idx, "family") != LUA_TNIL)
		*family = (uint8_t)luaL_checkinteger(L, -1);
	lua_pop(L, 1);
	if (lua_getfield(L, idx, "mark") != LUA_TNIL) {
		*mark = (uint32_t)luaL_checkinteger(L, -1);
		*have_mark = 1;
	}
	lua_pop(L, 1);
	if (lua_getfield(L, idx, "mask") != LUA_TNIL)
		*mask = (uint32_t)luaL_checkinteger(L, -1);
	lua_pop(L, 1);

	if (*have_mark && *mask == 0)
		*mask = 0xffffffff;
}

/* Register the collector, run the (optionally mark-filtered) query, unregister.
 * Returns the nfct_query result: < 0 on failure, with errno set. */
static int luact_query(struct nfct_handle *h, uint8_t family, int have_mark,
	uint32_t mark, uint32_t mask, luact_collect *c)
{
	if (nfct_callback_register(h, NFCT_T_ALL, luact_collect_cb, c) < 0)
		return -1;

	int rc;
	if (have_mark) {
		struct nfct_filter_dump *filter = nfct_filter_dump_create();
		if (filter == NULL) {
			nfct_callback_unregister(h);
			return -1;
		}
		struct nfct_filter_dump_mark fm = { .val = mark, .mask = mask };
		nfct_filter_dump_set_attr(filter, NFCT_FILTER_DUMP_MARK, &fm);
		if (family != AF_UNSPEC)
			nfct_filter_dump_set_attr_u8(filter, NFCT_FILTER_DUMP_L3NUM, family);
		rc = nfct_query(h, NFCT_Q_DUMP_FILTER, filter);
		nfct_filter_dump_destroy(filter);
	}
	else {
		rc = nfct_query(h, NFCT_Q_DUMP, &family);
	}

	nfct_callback_unregister(h);
	return rc;
}

/***
 * List conntrack entries, optionally filtered by mark, returning an array of
 * per-flow tables `{saddr, daddr, sport, dport, proto, family, mark,
 * orig_bytes, repl_bytes, orig_packets, repl_packets}`.
 * @function list
 * @tparam[opt] table opts `mark`/`mask` (kernel-side mark filter; mask defaults
 *   to all-ones when only `mark` is given) and `family` (address family, default
 *   `conntrack.AF_UNSPEC` = all families; `conntrack.AF_INET` or
 *   `conntrack.AF_INET6` to restrict).
 * @treturn table array of flow tables
 * @raise Error if the query fails or the handle is closed.
 * @usage
 * local flows = ct:list{ mark = 0x02000000, mask = 0x02000000 }
 */
static int luact_list(lua_State *L)
{
	struct nfct_handle *h = luact_check(L, 1);
	uint8_t family;
	uint32_t mark;
	uint32_t mask;
	int have_mark;

	luact_read_opts(L, 2, &family, &mark, &mask, &have_mark);

	luact_collect c = { NULL, 0, 0, 0 };
	int rc = luact_query(h, family, have_mark, mark, mask, &c);
	int saved = errno;

	if (c.oom) {
		free(c.flows);
		return luaL_error(L, "out of memory collecting conntrack entries");
	}
	if (rc < 0) {
		free(c.flows);
		return luaL_error(L, "conntrack list failed: %s", strerror(saved));
	}

	luact_build(L, &c);
	free(c.flows);
	return 1;
}

/***
 * Close the conntrack handle and free resources.
 * Idempotent; also called via `__gc` and `__close`.
 * @function close
 */
static int luact_close(lua_State *L)
{
	struct nfct_handle **ud = (struct nfct_handle **)luaL_checkudata(L, 1, LUACT_HANDLE);
	if (*ud != NULL) {
		nfct_close(*ud);
		*ud = NULL;
	}
	return 0;
}

static const luaL_Reg luact_methods[] = {
	{"list",	luact_list},
	{"close",	luact_close},
	{"__gc",	luact_close},
	{"__close",	luact_close},
	{NULL, NULL}
};

static const luaL_Reg luact_lib[] = {
	{"open",	luact_open},
	{NULL, NULL}
};

/* Address families (used by the `family` option and field) and the common L4
 * protocols, exported as module fields so callers avoid raw numbers. `proto` is
 * the raw IP protocol number, so any value can appear; these are the usual ones. */
static const struct {
	const char *name;
	lua_Integer value;
} luact_constants[] = {
	{"AF_UNSPEC",      AF_UNSPEC},
	{"AF_INET",        AF_INET},
	{"AF_INET6",       AF_INET6},
	{"IPPROTO_TCP",    IPPROTO_TCP},
	{"IPPROTO_UDP",    IPPROTO_UDP},
	{"IPPROTO_ICMP",   IPPROTO_ICMP},
	{"IPPROTO_ICMPV6", IPPROTO_ICMPV6},
	{NULL, 0}
};

int luaopen_conntrack(lua_State *L)
{
	luaL_newmetatable(L, LUACT_HANDLE);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, luact_methods, 0);
	lua_pop(L, 1);

	luaL_newlib(L, luact_lib);

	for (int i = 0; luact_constants[i].name != NULL; i++) {
		lua_pushinteger(L, luact_constants[i].value);
		lua_setfield(L, -2, luact_constants[i].name);
	}

	return 1;
}

