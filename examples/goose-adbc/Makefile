# Isolated goose + ADBC Flight SQL example. Does not participate in the
# default duckbox CMake/Make build or CI.
ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DEPS := $(ROOT).deps
GOOSE_VERSION ?= v2026.3
GOOSE ?= $(DEPS)/goose-$(GOOSE_VERSION)/goose
# Generated C must be compiled as C (g++ rejects goose's string literals).
# clang as `cc` still needs gcc's libstdc++ directory to resolve -lstdc++.
CXX ?= /usr/bin/g++
AR ?= ar
CXXFLAGS ?= -O2 -fPIC -std=c++17 -Wno-unused-parameter
STDCXX_DIR := $(dir $(shell $(CXX) -print-file-name=libstdc++.so))

ADBC_INC := $(DEPS)/adbc/include
ADBC_LIB := $(DEPS)/adbc/lib
ADBC_SRC := $(DEPS)/adbc/src
MANAGER_A := $(ADBC_LIB)/libadbc_driver_manager.a
FLIGHTSQL_SO := $(ADBC_LIB)/libadbc_driver_flightsql.so

.PHONY: all deps manager query run clean

all: query

deps:
	bash $(ROOT)scripts/fetch_deps.sh

$(GOOSE) $(ADBC_INC)/arrow-adbc/adbc.h $(FLIGHTSQL_SO):
	bash $(ROOT)scripts/fetch_deps.sh

$(MANAGER_A): $(ADBC_INC)/arrow-adbc/adbc.h $(ADBC_SRC)/adbc_driver_manager.cc
	mkdir -p $(ADBC_LIB) $(ROOT)build
	$(CXX) $(CXXFLAGS) -DADBC_EXPORTING -I$(ADBC_INC) -c $(ADBC_SRC)/adbc_driver_manager.cc \
	  -o $(ROOT)build/adbc_driver_manager.o
	$(AR) rcs $@ $(ROOT)build/adbc_driver_manager.o

query: $(GOOSE) $(MANAGER_A) $(FLIGHTSQL_SO) $(ROOT)query.goose $(ROOT)duckbox.goose $(ROOT)query.build $(ROOT)shim/adbc_backend.c
	cd $(ROOT) && \
	  LIBRARY_PATH="$(ADBC_LIB):$(STDCXX_DIR)$${LIBRARY_PATH:+:$$LIBRARY_PATH}" \
	  CPATH="$(ADBC_INC)$${CPATH:+:$$CPATH}" \
	  "$(GOOSE)" build query.goose

run: query
	$(ROOT)query

clean:
	rm -f $(ROOT)query
	rm -rf $(ROOT)build
