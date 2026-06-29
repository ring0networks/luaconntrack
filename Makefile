LUA_VERSION ?= $(shell for v in 5.5 5.4; do pkg-config --exists lua$$v 2>/dev/null && echo $$v && break; done)

LUA_INC  ?= $(shell pkg-config --cflags lua$(LUA_VERSION) 2>/dev/null || echo -I/usr/include/lua$(LUA_VERSION))
CT_INC   ?= $(shell pkg-config --cflags libnetfilter_conntrack 2>/dev/null)
CT_LIB   ?= $(shell pkg-config --libs libnetfilter_conntrack 2>/dev/null || echo -lnetfilter_conntrack)
CFLAGS   ?= -O2 -Wall -Wextra -fPIC
LDFLAGS  ?= -shared

LUA_CMOD ?= /usr/local/lib/lua/$(LUA_VERSION)

conntrack.so: luaconntrack.c
	$(CC) $(CFLAGS) $(LUA_INC) $(CT_INC) -o $@ $< $(LDFLAGS) $(CT_LIB)

install: conntrack.so
	install -D -m 0755 $< $(DESTDIR)$(LUA_CMOD)/$<

clean:
	rm -f conntrack.so

.PHONY: install clean
