# Thin wrapper around CMake, similar in spirit to the community-extension Makefile:
# fetch deps, build, run C++ enforcement tests.
PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(PROJ_DIR)build
CMAKE ?= cmake
CXX ?= g++

.PHONY: deps configure build test serve seed-local clean

deps:
	bash $(PROJ_DIR)scripts/fetch_deps.sh

configure: deps
	$(CMAKE) -S $(PROJ_DIR) -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=$(CXX)

build: configure
	$(CMAKE) --build $(BUILD_DIR) --parallel

test: build
	$(BUILD_DIR)/duckbox_tests

serve: build
	$(BUILD_DIR)/duckbox serve --policies $(PROJ_DIR)policies/memory --listen 127.0.0.1:4747

seed-local: build
	$(BUILD_DIR)/duckbox seed --policies $(PROJ_DIR)policies/memory

clean:
	rm -rf $(BUILD_DIR)
