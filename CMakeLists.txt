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
   NOT EXISTS "${DUCKBOX_DEPS}/yaml-cpp/CMakeLists.txt" OR
   NOT EXISTS "${DUCKBOX_DEPS}/nlohmann/nlohmann/json.hpp" OR
   NOT EXISTS "${DUCKBOX_DEPS}/jwt-cpp/include/jwt-cpp/jwt.h" OR
   NOT EXISTS "${DUCKBOX_DEPS}/cli11/CLI/CLI.hpp" OR
   NOT EXISTS "${DUCKBOX_DEPS}/cppcodec/cppcodec/base64_url_unpadded.hpp")
  message(STATUS "Fetching DuckDB ${DUCKBOX_DUCKDB_VERSION} and httplib into ${DUCKBOX_DEPS}")
  execute_process(
    COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/fetch_deps.sh"
    RESULT_VARIABLE _fetch_rv)
  if(NOT _fetch_rv EQUAL 0)
    message(FATAL_ERROR "scripts/fetch_deps.sh failed")
  endif()
endif()

# yaml-cpp 0.9.0: cmake_minimum_required 3.5...3.30 so CMake 4 accepts it.
# 0.8.0 declared 3.4 and fails on Homebrew CMake 4 (no 0.8.1; 0.9.0 is the fix).
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
if(EXISTS "${DUCKBOX_DEPS}/yaml-cpp/CMakeLists.txt")
  add_subdirectory("${DUCKBOX_DEPS}/yaml-cpp" "${CMAKE_BINARY_DIR}/yaml-cpp" EXCLUDE_FROM_ALL)
else()
  include(FetchContent)
  FetchContent_Declare(
    yaml-cpp
    URL https://github.com/jbeder/yaml-cpp/archive/refs/tags/yaml-cpp-0.9.0.tar.gz
    URL_HASH SHA256=25cb043240f828a8c51beb830569634bc7ac603978e0f69d6b63558dadefd49a)
  FetchContent_MakeAvailable(yaml-cpp)
endif()

# nlohmann/json: registry records, JWT payloads, audit/debug JSON. Never a homemade parser.
if(NOT EXISTS "${DUCKBOX_DEPS}/nlohmann/nlohmann/json.hpp")
  include(FetchContent)
  FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
    URL_HASH SHA256=9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6
    DOWNLOAD_NO_EXTRACT TRUE)
  FetchContent_GetProperties(nlohmann_json)
  if(NOT nlohmann_json_POPULATED)
    FetchContent_Populate(nlohmann_json)
    file(MAKE_DIRECTORY "${DUCKBOX_DEPS}/nlohmann/nlohmann")
    file(COPY "${nlohmann_json_SOURCE_DIR}/json.hpp" DESTINATION "${DUCKBOX_DEPS}/nlohmann/nlohmann")
  endif()
endif()

# jwt-cpp: HS256 JWT verification (OpenSSL backend, nlohmann traits). Never a homemade verifier.
if(NOT EXISTS "${DUCKBOX_DEPS}/jwt-cpp/include/jwt-cpp/jwt.h")
  include(FetchContent)
  FetchContent_Declare(
    jwt_cpp
    URL https://github.com/Thalhammer/jwt-cpp/archive/refs/tags/v0.7.0.tar.gz
    URL_HASH SHA256=b9eb270e3ba8221e4b2bc38723c9a1cb4fa6c241a42908b9a334daff31137406)
  FetchContent_GetProperties(jwt_cpp)
  if(NOT jwt_cpp_POPULATED)
    FetchContent_Populate(jwt_cpp)
    file(MAKE_DIRECTORY "${DUCKBOX_DEPS}/jwt-cpp")
    file(COPY "${jwt_cpp_SOURCE_DIR}/include" DESTINATION "${DUCKBOX_DEPS}/jwt-cpp")
  endif()
endif()

# CLI11: duckbox CLI (serve/sandbox/run/validate). Header-only.
if(NOT EXISTS "${DUCKBOX_DEPS}/cli11/CLI/CLI.hpp")
  include(FetchContent)
  FetchContent_Declare(
    cli11
    URL https://github.com/CLIUtils/CLI11/releases/download/v2.4.2/CLI11.hpp
    URL_HASH SHA256=3935283e4c9db7089ed304476dbab2805c9311c41b125a55e92da4659df0d660
    DOWNLOAD_NO_EXTRACT TRUE)
  FetchContent_GetProperties(cli11)
  if(NOT cli11_POPULATED)
    FetchContent_Populate(cli11)
    file(MAKE_DIRECTORY "${DUCKBOX_DEPS}/cli11/CLI")
    file(COPY "${cli11_SOURCE_DIR}/CLI11.hpp" DESTINATION "${DUCKBOX_DEPS}/cli11/CLI")
    file(RENAME "${DUCKBOX_DEPS}/cli11/CLI/CLI11.hpp" "${DUCKBOX_DEPS}/cli11/CLI/CLI.hpp")
  endif()
endif()

# cppcodec: Base64URL (unpadded) for handles, spec payloads, JWT test helpers.
if(NOT EXISTS "${DUCKBOX_DEPS}/cppcodec/cppcodec/base64_url_unpadded.hpp")
  include(FetchContent)
  FetchContent_Declare(
    cppcodec
    URL https://github.com/tplgy/cppcodec/archive/refs/tags/v0.2.tar.gz
    URL_HASH SHA256=0edaea2a9d9709d456aa99a1c3e17812ed130f9ef2b5c2d152c230a5cbc5c482)
  FetchContent_GetProperties(cppcodec)
  if(NOT cppcodec_POPULATED)
    FetchContent_Populate(cppcodec)
    file(MAKE_DIRECTORY "${DUCKBOX_DEPS}/cppcodec")
    file(COPY "${cppcodec_SOURCE_DIR}/cppcodec" DESTINATION "${DUCKBOX_DEPS}/cppcodec")
  endif()
endif()

# On macOS, Homebrew Arrow/gRPC already load openssl@4. Linking a second
# OpenSSL (vcpkg 3.5 static) into the same binary aborts in AWS ClientConfiguration.
# Prefer Homebrew aws-sdk-cpp + openssl@4 on Darwin; keep vcpkg on Linux.
if(APPLE)
  set(DUCKBOX_USE_HOMEBREW_AWS ON)
  execute_process(COMMAND brew --prefix aws-sdk-cpp OUTPUT_VARIABLE _brew_aws OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  execute_process(COMMAND brew --prefix openssl@4 OUTPUT_VARIABLE _brew_ssl OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(_brew_aws)
    list(PREPEND CMAKE_PREFIX_PATH "${_brew_aws}")
  endif()
  if(_brew_ssl)
    set(OPENSSL_ROOT_DIR "${_brew_ssl}" CACHE PATH "" FORCE)
    list(PREPEND CMAKE_PREFIX_PATH "${_brew_ssl}")
  endif()
endif()

# aws-sdk-cpp S3 (vcpkg) before Arrow so OpenSSL::Crypto is vcpkg 3.5, matching curl/s2n.
# Arrow S3FileSystem has no If-Match / If-None-Match.
set(_duckbox_vcpkg "$ENV{VCPKG_ROOT}")
if(NOT _duckbox_vcpkg)
  set(_duckbox_vcpkg "${DUCKBOX_DEPS}/vcpkg")
endif()
set(_duckbox_vcpkg_installed "$ENV{DUCKBOX_VCPKG_INSTALLED}")
if(NOT _duckbox_vcpkg_installed)
  set(_duckbox_vcpkg_installed "${DUCKBOX_DEPS}/vcpkg_installed")
endif()
set(_duckbox_triplets "$ENV{VCPKG_DEFAULT_TRIPLET};x64-linux;arm64-linux")
set(_duckbox_vcpkg_prefixes
  "${_duckbox_vcpkg_installed}"
  "${_duckbox_vcpkg}/installed")
macro(duckbox_find_vcpkg_aws)
  foreach(_duckbox_prefix IN LISTS _duckbox_vcpkg_prefixes)
    foreach(_duckbox_triplet IN LISTS _duckbox_triplets)
      if(NOT _duckbox_triplet)
        continue()
      endif()
      if(EXISTS "${_duckbox_prefix}/${_duckbox_triplet}/share/aws-cpp-sdk-s3/aws-cpp-sdk-s3-config.cmake" OR
         EXISTS "${_duckbox_prefix}/${_duckbox_triplet}/share/awssdk/AWSSDKConfig.cmake" OR
         EXISTS "${_duckbox_prefix}/${_duckbox_triplet}/share/aws-sdk-cpp/AWSSDKConfig.cmake" OR
         EXISTS "${_duckbox_prefix}/${_duckbox_triplet}/share/AWSSDK/AWSSDKConfig.cmake")
        list(PREPEND CMAKE_PREFIX_PATH "${_duckbox_prefix}/${_duckbox_triplet}")
        set(DUCKBOX_VCPKG_LIB "${_duckbox_prefix}/${_duckbox_triplet}/lib")
        break()
      endif()
    endforeach()
    if(DUCKBOX_VCPKG_LIB)
      break()
    endif()
  endforeach()
endmacro()
if(APPLE AND DUCKBOX_USE_HOMEBREW_AWS)
  # Do not prepend vcpkg: its static OpenSSL 3.5 fights Homebrew openssl@4 from Arrow/gRPC.
  message(STATUS "Using Homebrew aws-sdk-cpp / openssl@4 on Apple")
else()
  duckbox_find_vcpkg_aws()
endif()

if(NOT APPLE)
# curl/s2n from vcpkg were built against vcpkg OpenSSL 3.5; do not mix system 3.0.
# Debug coverage links vcpkg's debug curl/s2n, so OpenSSL must be the debug copy too.
if(DUCKBOX_VCPKG_LIB)
  set(OPENSSL_ROOT_DIR "${DUCKBOX_VCPKG_LIB}/..")
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND EXISTS "${OPENSSL_ROOT_DIR}/debug/lib/libcrypto.a")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/debug/lib/libcrypto.a" CACHE FILEPATH "" FORCE)
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/debug/lib/libssl.a" CACHE FILEPATH "" FORCE)
  elseif(OPENSSL_CRYPTO_LIBRARY MATCHES "/debug/lib/")
    unset(OPENSSL_CRYPTO_LIBRARY CACHE)
    unset(OPENSSL_SSL_LIBRARY CACHE)
  endif()
endif()
endif()
find_package(OpenSSL REQUIRED)

if(DUCKBOX_VCPKG_LIB)
  set(AWSSDK_ROOT_DIR "${DUCKBOX_VCPKG_LIB}/.." CACHE PATH "vcpkg aws-sdk-cpp prefix")
endif()
find_package(aws-cpp-sdk-s3 CONFIG QUIET)
if(NOT aws-cpp-sdk-s3_FOUND)
  find_package(AWSSDK QUIET COMPONENTS s3)
endif()
if(NOT aws-cpp-sdk-s3_FOUND AND NOT AWSSDK_FOUND)
  if(APPLE)
    message(FATAL_ERROR "Homebrew aws-sdk-cpp not found. brew install aws-sdk-cpp openssl@4")
  endif()
  message(STATUS "AWS SDK C++ (S3) not found; running scripts/install_aws_sdk.sh")
  execute_process(
    COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/install_aws_sdk.sh"
    RESULT_VARIABLE _aws_rv)
  if(NOT _aws_rv EQUAL 0)
    message(FATAL_ERROR "scripts/install_aws_sdk.sh failed")
  endif()
  duckbox_find_vcpkg_aws()
  set(AWSSDK_ROOT_DIR "${DUCKBOX_VCPKG_LIB}/.." CACHE PATH "vcpkg aws-sdk-cpp prefix" FORCE)
  find_package(aws-cpp-sdk-s3 CONFIG REQUIRED)
endif()
if(DUCKBOX_VCPKG_LIB)
  set(CMAKE_BUILD_RPATH "${DUCKBOX_VCPKG_LIB}")
  set(CMAKE_INSTALL_RPATH "${DUCKBOX_VCPKG_LIB}")
endif()

find_package(Arrow CONFIG REQUIRED)
find_package(ArrowFlight CONFIG REQUIRED)
find_package(ArrowFlightSql CONFIG REQUIRED)

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
    ${DUCKBOX_DEPS}/httplib
    ${DUCKBOX_DEPS}/nlohmann
    ${DUCKBOX_DEPS}/jwt-cpp/include
    ${DUCKBOX_DEPS}/cppcodec)
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
  OpenSSL::SSL
  OpenSSL::Crypto
  yaml-cpp)
if(TARGET aws-cpp-sdk-s3)
  # Homebrew's exported s3 target lists core as a dependent lib, not INTERFACE.
  find_package(aws-cpp-sdk-core CONFIG QUIET)
  if(TARGET aws-cpp-sdk-core)
    target_link_libraries(duckbox_core PUBLIC aws-cpp-sdk-core)
  endif()
  target_link_libraries(duckbox_core PUBLIC aws-cpp-sdk-s3)
else()
  target_include_directories(duckbox_core PUBLIC ${AWSSDK_INCLUDE_DIRS})
  target_link_libraries(duckbox_core PUBLIC ${AWSSDK_LIBRARIES})
endif()
if(APPLE)
  target_link_libraries(duckbox_core PUBLIC
    "-framework CoreFoundation"
    "-framework Security"
    "-framework SystemConfiguration")
endif()

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
  duckdb_fsst)
# Official macOS static-libs zip does not include libduckdb_jemalloc.a.
if(EXISTS "${_duckdb_libdir}/libduckdb_jemalloc.a")
  list(APPEND _duckdb_libs duckdb_jemalloc)
endif()

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
target_include_directories(duckbox PRIVATE ${DUCKBOX_DEPS}/cli11)
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
  test/unit/metrics_test.cpp
  test/unit/s3_test.cpp
  test/unit/lease_test.cpp
  test/unit/membership_test.cpp)

duckbox_add_test(duckbox_guardrail_tests
  test/support/check.cpp
  test/guardrails/runner.cpp)

duckbox_add_test(duckbox_integration_tests
  test/support/check.cpp
  test/integration/main.cpp
  test/integration/sandbox_exec_test.cpp
  test/integration/runtime_test.cpp
  test/integration/s3_registry_test.cpp
  test/integration/auth_flight_test.cpp
  test/integration/cluster_test.cpp)

enable_testing()
add_test(NAME unit COMMAND duckbox_unit_tests)
add_test(NAME guardrails COMMAND duckbox_guardrail_tests)
add_test(NAME integration COMMAND duckbox_integration_tests)
set_tests_properties(unit PROPERTIES LABELS "unit")
set_tests_properties(guardrails PROPERTIES LABELS "guardrails")
set_tests_properties(integration PROPERTIES LABELS "integration")
