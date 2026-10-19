cmake_minimum_required(VERSION 3.20)
project(duckbox LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(DUCKBOX_DUCKDB_VERSION "v1.5.6")

if(NOT DEFINED ENV{DUCKBOX_DEPS})
  set(DUCKBOX_DEPS "${CMAKE_SOURCE_DIR}/.deps")
else()
  set(DUCKBOX_DEPS "$ENV{DUCKBOX_DEPS}")
endif()

if(NOT EXISTS "${DUCKBOX_DEPS}/duckdb/include/duckdb/parser/parser.hpp" OR
   NOT EXISTS "${DUCKBOX_DEPS}/duckdb/lib/libduckdb_static.a" OR
   NOT EXISTS "${DUCKBOX_DEPS}/httplib/httplib.h" OR
   NOT EXISTS "${DUCKBOX_DEPS}/yaml-cpp-0.8.0/CMakeLists.txt")
  message(STATUS "Fetching DuckDB ${DUCKBOX_DUCKDB_VERSION} and httplib into ${DUCKBOX_DEPS}")
  execute_process(
    COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/fetch_deps.sh"
    RESULT_VARIABLE _fetch_rv)
  if(NOT _fetch_rv EQUAL 0)
    message(FATAL_ERROR "scripts/fetch_deps.sh failed")
  endif()
endif()

find_package(Arrow CONFIG REQUIRED)
find_package(ArrowFlight CONFIG REQUIRED)
find_package(ArrowFlightSql CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# yaml-cpp: specs and daemon config are security-relevant; never use a homemade parser.
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
if(EXISTS "${DUCKBOX_DEPS}/yaml-cpp-0.8.0/CMakeLists.txt")
  add_subdirectory("${DUCKBOX_DEPS}/yaml-cpp-0.8.0" "${CMAKE_BINARY_DIR}/yaml-cpp" EXCLUDE_FROM_ALL)
else()
  include(FetchContent)
  FetchContent_Declare(
    yaml-cpp
    URL https://github.com/jbeder/yaml-cpp/archive/refs/tags/0.8.0.tar.gz
    URL_HASH SHA256=fbe74bbdcee21d656715688706da3c8becfd946d92cd44705cc6098bb23b3a16)
  FetchContent_MakeAvailable(yaml-cpp)
endif()

set(DUCKBOX_SOURCES
  server/src/yaml.cpp
  server/src/error.cpp
  server/src/crypto.cpp
  server/src/secrets.cpp
  server/src/policy.cpp
  server/src/daemon_config.cpp
  server/src/tenant_key.cpp
  server/src/validator.cpp
  server/src/rewriter.cpp
  server/src/plan_check.cpp
  server/src/lease.cpp
  server/src/metrics.cpp
  server/src/lake.cpp
  server/src/init_sql.cpp
  server/src/spec_validator.cpp
  server/src/sandbox.cpp
  server/src/s3.cpp
  server/src/sandbox_registry.cpp
  server/src/arrow_ipc.cpp
  server/src/auth.cpp
  server/src/handle.cpp
  server/src/flight_sql_server.cpp
  server/src/http_server.cpp)

add_library(duckbox_core STATIC ${DUCKBOX_SOURCES})
target_include_directories(duckbox_core
  PUBLIC
    ${CMAKE_SOURCE_DIR}/server/include
    ${DUCKBOX_DEPS}/duckdb/include
    ${DUCKBOX_DEPS}/httplib)
target_compile_definitions(duckbox_core PUBLIC DUCKBOX_DUCKDB_VERSION="${DUCKBOX_DUCKDB_VERSION}")
if(NOT MSVC)
  target_compile_options(duckbox_core PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

option(DUCKBOX_COVERAGE "Build duckbox_core with gcov (--coverage -O0)" OFF)
if(DUCKBOX_COVERAGE AND NOT MSVC)
  target_compile_options(duckbox_core PUBLIC --coverage -O0 -g)
  target_link_options(duckbox_core PUBLIC --coverage)
  target_link_libraries(duckbox_core PUBLIC gcov)
endif()
target_link_libraries(duckbox_core PUBLIC
  Arrow::arrow_shared
  ArrowFlight::arrow_flight_shared
  ArrowFlightSql::arrow_flight_sql_shared
  OpenSSL::Crypto
  yaml-cpp)

set(_duckdb_libdir "${DUCKBOX_DEPS}/duckdb/lib")
set(_duckdb_libs
  duckdb_static
  parquet_extension
  core_functions_extension
  json_extension
  icu_extension
  autocomplete_extension
  duckdb_generated_extension_loader
  duckdb_fmt
  duckdb_pg_query
  duckdb_re2
  duckdb_zstd
  duckdb_miniz
  duckdb_utf8proc
  duckdb_hyperloglog
  duckdb_fastpforlib
  duckdb_skiplistlib
  duckdb_yyjson
  duckdb_mbedtls
  duckdb_fsst
  duckdb_jemalloc)

set(_duckdb_link_files)
foreach(_lib ${_duckdb_libs})
  list(APPEND _duckdb_link_files "${_duckdb_libdir}/lib${_lib}.a")
endforeach()

function(duckbox_link_duckdb target)
  if(APPLE)
    target_link_libraries(${target} PRIVATE ${_duckdb_link_files} pthread dl)
  else()
    target_link_libraries(${target} PRIVATE
      -Wl,--start-group ${_duckdb_link_files} -Wl,--end-group
      pthread dl)
  endif()
endfunction()

duckbox_link_duckdb(duckbox_core)

add_executable(duckbox server/src/main.cpp)
target_link_libraries(duckbox PRIVATE duckbox_core)
duckbox_link_duckdb(duckbox)

function(duckbox_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE duckbox_core)
  duckbox_link_duckdb(${name})
  target_include_directories(${name} PRIVATE
    ${CMAKE_SOURCE_DIR}/test/support
    ${CMAKE_SOURCE_DIR}/test/unit
    ${CMAKE_SOURCE_DIR}/test/integration)
  target_compile_definitions(${name} PRIVATE
    DUCKBOX_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
endfunction()

duckbox_add_test(duckbox_unit_tests
  test/support/check.cpp
  test/unit/main.cpp
  test/unit/tenant_key_test.cpp
  test/unit/spec_loader_test.cpp
  test/unit/validator_test.cpp
  test/unit/rewriter_test.cpp
  test/unit/plan_guard_test.cpp
  test/unit/init_sql_test.cpp
  test/unit/handle_test.cpp
  test/unit/crypto_test.cpp
  test/unit/registry_test.cpp
  test/unit/metrics_test.cpp)

duckbox_add_test(duckbox_guardrail_tests
  test/support/check.cpp
  test/guardrails/runner.cpp)

duckbox_add_test(duckbox_integration_tests
  test/support/check.cpp
  test/integration/main.cpp
  test/integration/sandbox_exec_test.cpp
  test/integration/runtime_test.cpp
  test/integration/s3_registry_test.cpp
  test/integration/auth_flight_test.cpp)

enable_testing()
add_test(NAME unit COMMAND duckbox_unit_tests)
add_test(NAME guardrails COMMAND duckbox_guardrail_tests)
add_test(NAME integration COMMAND duckbox_integration_tests)
set_tests_properties(unit PROPERTIES LABELS "unit")
set_tests_properties(guardrails PROPERTIES LABELS "guardrails")
set_tests_properties(integration PROPERTIES LABELS "integration")
