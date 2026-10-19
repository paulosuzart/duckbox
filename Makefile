PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(PROJ_DIR)build
CMAKE ?= cmake
CXX ?= g++

.PHONY: deps arrow configure build test serve run-memory validate clean

deps:
	bash $(PROJ_DIR)scripts/fetch_deps.sh

arrow:
	bash $(PROJ_DIR)scripts/install_arrow.sh

configure: deps
	$(CMAKE) -S $(PROJ_DIR) -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=$(CXX)

build: configure
	$(CMAKE) --build $(BUILD_DIR) --parallel

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

serve: build
	$(BUILD_DIR)/duckbox serve --daemon $(PROJ_DIR)daemons/memory.yaml --listen 127.0.0.1:4747

run-memory: build
	$(BUILD_DIR)/duckbox run --daemon $(PROJ_DIR)daemons/memory.yaml \
	  --spec $(PROJ_DIR)policies/memory/analyst.yaml \
	  --key tenant_21:user_sergio \
	  --sql 'SELECT id, title, amount FROM deals ORDER BY id'

validate: build
	$(BUILD_DIR)/duckbox validate --daemon $(PROJ_DIR)daemons/memory.yaml \
	  --spec $(PROJ_DIR)policies/memory/analyst.yaml

clean:
	rm -rf $(BUILD_DIR)
