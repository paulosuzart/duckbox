# Isolated C3 + ADBC Flight SQL example. Not part of the default duckbox build.
ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
C3C ?= c3c
LIBDIR := $(ROOT).deps/adbc/lib
ifeq ($(shell uname -s),Darwin)
DRIVER := $(LIBDIR)/libadbc_driver_flightsql.dylib
RPATH := @executable_path/../.deps/adbc/lib
# The wheel's dylib id is a bare file name (libadbc_driver_flightsql.112.0.0.dylib),
# so point the binary at @rpath and re-sign it ad hoc (arm64 requires a signature).
FIXUP = install_name_tool -change "$$(otool -D $(DRIVER) | tail -n 1)" \
	@rpath/libadbc_driver_flightsql.dylib $(ROOT)build/query && \
	codesign -f -s - $(ROOT)build/query
else
DRIVER := $(LIBDIR)/libadbc_driver_flightsql.so
RPATH := $$ORIGIN/../.deps/adbc/lib
FIXUP = true
endif
SRC := src/main.c3 src/adbc.c3

.PHONY: all deps run

all: $(ROOT)build/query

deps:
	bash $(ROOT)scripts/fetch_deps.sh

$(DRIVER):
	bash $(ROOT)scripts/fetch_deps.sh

# The Flight SQL library exports AdbcDatabaseNew / AdbcStatementExecuteQuery / ...
$(ROOT)build/query: $(DRIVER) $(addprefix $(ROOT),$(SRC))
	mkdir -p $(ROOT)build
	cd $(ROOT) && $(C3C) compile -O1 --output-dir build -o query $(SRC) \
		-L $(LIBDIR) -l adbc_driver_flightsql -z -rpath -z '$(RPATH)'
	$(FIXUP)

run: all
	$(ROOT)build/query
