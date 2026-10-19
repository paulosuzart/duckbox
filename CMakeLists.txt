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
   NOT EXISTS "${DUCKBOX_DEPS}/httplib/httplib.h")
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
target_link_libraries(duckbox_core PUBLIC
  Arrow::arrow_shared
  ArrowFlight::arrow_flight_shared
  ArrowFlightSql::arrow_flight_sql_shared
  OpenSSL::Crypto)

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

add_executable(duckbox_tests test/test_enforcement.cpp)
target_link_libraries(duckbox_tests PRIVATE duckbox_core)
duckbox_link_duckdb(duckbox_tests)
target_compile_definitions(duckbox_tests PRIVATE
  DUCKBOX_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

enable_testing()
add_test(NAME enforcement COMMAND duckbox_tests)
