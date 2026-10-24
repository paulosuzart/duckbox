# Isolated Zig + ADBC Flight SQL example. Not part of the default duckbox build.
ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ZIG ?= zig
ADBC_INC := $(ROOT).deps/adbc/include
FLIGHTSQL_SO := $(ROOT).deps/adbc/lib/libadbc_driver_flightsql.so

.PHONY: all deps query run clean

all: query

deps:
	bash $(ROOT)scripts/fetch_deps.sh

$(ADBC_INC)/arrow-adbc/adbc.h $(FLIGHTSQL_SO):
	bash $(ROOT)scripts/fetch_deps.sh

query: $(ADBC_INC)/arrow-adbc/adbc.h $(FLIGHTSQL_SO) $(ROOT)src/main.zig $(ROOT)build.zig
	cd $(ROOT) && $(ZIG) build -Doptimize=ReleaseSafe
	ln -sfn zig-out/bin/query $(ROOT)query

run: query
	$(ROOT)zig-out/bin/query

clean:
	rm -f $(ROOT)query
	rm -rf $(ROOT)zig-out $(ROOT).zig-cache
