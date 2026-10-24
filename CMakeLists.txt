cmake_minimum_required(VERSION 3.20)
project(duckbox LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(DUCKBOX_DUCKDB_VERSION "v2.0.0")

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
  execute_process(COMMAND brew --prefix abseil OUTPUT_VARIABLE _brew_absl OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(_brew_aws)
    list(PREPEND CMAKE_PREFIX_PATH "${_brew_aws}")
  endif()
  if(_brew_ssl)
    set(OPENSSL_ROOT_DIR "${_brew_ssl}" CACHE PATH "" FORCE)
    list(PREPEND CMAKE_PREFIX_PATH "${_brew_ssl}")
  endif()
  if(_brew_absl)
    list(PREPEND CMAKE_PREFIX_PATH "${_brew_absl}")
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
find_package(aws-cpp-sdk-sts CONFIG QUIET)
find_package(aws-cpp-sdk-identity-management CONFIG QUIET)
find_package(aws-cpp-sdk-cognito-identity CONFIG QUIET)
if(NOT aws-cpp-sdk-s3_FOUND)
  find_package(AWSSDK QUIET COMPONENTS s3 sts identity-management)
endif()
set(_duckbox_aws_sts_ok FALSE)
if(TARGET aws-cpp-sdk-sts AND TARGET aws-cpp-sdk-identity-management)
  set(_duckbox_aws_sts_ok TRUE)
elseif(AWSSDK_FOUND)
  set(_duckbox_aws_sts_ok TRUE)
endif()
if(NOT aws-cpp-sdk-s3_FOUND AND NOT AWSSDK_FOUND)
  if(APPLE)
    message(FATAL_ERROR "Homebrew aws-sdk-cpp not found. brew install aws-sdk-cpp openssl@4")
  endif()
  message(STATUS "AWS SDK C++ (S3/STS) not found; running scripts/install_aws_sdk.sh")
  execute_process(
    COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/install_aws_sdk.sh"
    RESULT_VARIABLE _aws_rv)
  if(NOT _aws_rv EQUAL 0)
    message(FATAL_ERROR "scripts/install_aws_sdk.sh failed")
  endif()
  duckbox_find_vcpkg_aws()
  set(AWSSDK_ROOT_DIR "${DUCKBOX_VCPKG_LIB}/.." CACHE PATH "vcpkg aws-sdk-cpp prefix" FORCE)
  find_package(aws-cpp-sdk-s3 CONFIG REQUIRED)
  find_package(aws-cpp-sdk-sts CONFIG REQUIRED)
  find_package(aws-cpp-sdk-identity-management CONFIG REQUIRED)
  set(_duckbox_aws_sts_ok TRUE)
elseif(NOT APPLE AND NOT _duckbox_aws_sts_ok)
  message(STATUS "AWS SDK C++ STS/identity-management missing; running scripts/install_aws_sdk.sh")
  execute_process(
    COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/install_aws_sdk.sh"
    RESULT_VARIABLE _aws_rv)
  if(NOT _aws_rv EQUAL 0)
    message(FATAL_ERROR "scripts/install_aws_sdk.sh failed")
  endif()
  duckbox_find_vcpkg_aws()
  set(AWSSDK_ROOT_DIR "${DUCKBOX_VCPKG_LIB}/.." CACHE PATH "vcpkg aws-sdk-cpp prefix" FORCE)
  find_package(aws-cpp-sdk-sts CONFIG REQUIRED)
  find_package(aws-cpp-sdk-identity-management CONFIG REQUIRED)
  set(_duckbox_aws_sts_ok TRUE)
endif()
if(NOT APPLE AND NOT _duckbox_aws_sts_ok)
  message(FATAL_ERROR "aws-sdk-cpp sts + identity-management are required for lease assume-role")
endif()
if(DUCKBOX_VCPKG_LIB)
  set(CMAKE_BUILD_RPATH "${DUCKBOX_VCPKG_LIB}")
  set(CMAKE_INSTALL_RPATH "${DUCKBOX_VCPKG_LIB}")
endif()

find_package(Arrow CONFIG REQUIRED)
find_package(ArrowFlight CONFIG REQUIRED)
find_package(ArrowFlightSql CONFIG REQUIRED)

# Abseil strings is already on the Arrow Flight / gRPC graph (libabsl-dev on
# Linux APT, Homebrew abseil via grpc on macOS). Link it explicitly so call
# sites do not depend on transitive include paths.
if(NOT TARGET absl::strings)
  find_package(absl CONFIG REQUIRED)
endif()
if(NOT TARGET absl::strings)
  message(FATAL_ERROR "absl::strings is required (Arrow Flight / gRPC / Homebrew abseil)")
endif()
message(STATUS "Using Abseil strings (absl::strings)")

# QueryErrorInjection is compiled only into test targets. The release duckbox
# binary links duckbox_core, which is built without this option.
option(DUCKBOX_TESTING "Compile QueryErrorInjection test seams (OFF in the release binary)" OFF)

set(DUCKBOX_SOURCES
  server/src/common/yaml.cpp
  server/src/common/error.cpp
  server/src/common/crypto.cpp
  server/src/common/duckdb_layer.cpp
  server/src/s3/secrets.cpp
  server/src/s3/s3.cpp
  server/src/s3/s3_credentials.cpp
  server/src/node/daemon_config.cpp
  server/src/config/policy.cpp
  server/src/config/spec_validator.cpp
  server/src/rewriter/tenant_key.cpp
  server/src/rewriter/validator.cpp
  server/src/rewriter/rewriter.cpp
  server/src/lake/lake.cpp
  server/src/metrics/metrics.cpp
  server/src/cluster/lease.cpp
  server/src/sandbox/sandbox_registry.cpp
  server/src/arrow/arrow_ipc.cpp
  server/src/arrow/arrow_types.cpp
  server/src/flight/auth.cpp
  server/src/flight/handle.cpp
  server/src/flight/flight_sql_server.cpp
  server/src/flight/http_server.cpp)
set(DUCKBOX_SANDBOX_SRC server/src/sandbox/sandbox.cpp)

function(duckbox_apply_core_compile target)
  target_include_directories(${target}
    PUBLIC
      ${CMAKE_SOURCE_DIR}/server/src
      ${DUCKBOX_DEPS}/duckdb/include
      ${DUCKBOX_DEPS}/httplib
      ${DUCKBOX_DEPS}/nlohmann
      ${DUCKBOX_DEPS}/jwt-cpp/include
      ${DUCKBOX_DEPS}/cppcodec)
  target_compile_definitions(${target} PUBLIC DUCKBOX_DUCKDB_VERSION="${DUCKBOX_DUCKDB_VERSION}")
  if(NOT MSVC)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
endfunction()

add_library(duckbox_objs OBJECT ${DUCKBOX_SOURCES})
add_library(duckbox_sandbox OBJECT ${DUCKBOX_SANDBOX_SRC})
add_library(duckbox_sandbox_testing OBJECT ${DUCKBOX_SANDBOX_SRC})
duckbox_apply_core_compile(duckbox_objs)
duckbox_apply_core_compile(duckbox_sandbox)
duckbox_apply_core_compile(duckbox_sandbox_testing)
target_compile_definitions(duckbox_sandbox_testing PRIVATE DUCKBOX_TESTING)

add_library(duckbox_core STATIC $<TARGET_OBJECTS:duckbox_objs> $<TARGET_OBJECTS:duckbox_sandbox>)
add_library(duckbox_core_testing STATIC $<TARGET_OBJECTS:duckbox_objs> $<TARGET_OBJECTS:duckbox_sandbox_testing>)
duckbox_apply_core_compile(duckbox_core)
duckbox_apply_core_compile(duckbox_core_testing)

option(DUCKBOX_COVERAGE "Build duckbox_core with gcov (--coverage -O0)" OFF)
if(DUCKBOX_COVERAGE AND NOT MSVC)
  foreach(_cov_tgt duckbox_objs duckbox_sandbox_testing duckbox_core duckbox_core_testing)
    target_compile_options(${_cov_tgt} PUBLIC --coverage -O0 -g)
  endforeach()
  target_link_options(duckbox_core PUBLIC --coverage)
  target_link_options(duckbox_core_testing PUBLIC --coverage)
  target_link_libraries(duckbox_core PUBLIC gcov)
  target_link_libraries(duckbox_core_testing PUBLIC gcov)
endif()

function(duckbox_link_core_deps target)
  target_link_libraries(${target} PUBLIC
    Arrow::arrow_shared
    ArrowFlight::arrow_flight_shared
    ArrowFlightSql::arrow_flight_sql_shared
    absl::strings
    OpenSSL::SSL
    OpenSSL::Crypto
    yaml-cpp)
  if(TARGET aws-cpp-sdk-s3)
    find_package(aws-cpp-sdk-core CONFIG QUIET)
    if(TARGET aws-cpp-sdk-core)
      target_link_libraries(${target} PUBLIC aws-cpp-sdk-core)
    endif()
    target_link_libraries(${target} PUBLIC aws-cpp-sdk-s3)
    if(TARGET aws-cpp-sdk-identity-management)
      target_link_libraries(${target} PUBLIC aws-cpp-sdk-identity-management)
    endif()
    if(TARGET aws-cpp-sdk-cognito-identity)
      target_link_libraries(${target} PUBLIC aws-cpp-sdk-cognito-identity)
    endif()
    if(TARGET aws-cpp-sdk-sts)
      target_link_libraries(${target} PUBLIC aws-cpp-sdk-sts)
    endif()
    if(TARGET aws-cpp-sdk-sts AND TARGET aws-cpp-sdk-identity-management)
      target_compile_definitions(${target} PUBLIC DUCKBOX_HAS_STS_ASSUME_ROLE=1)
    endif()
  else()
    target_include_directories(${target} PUBLIC ${AWSSDK_INCLUDE_DIRS})
    target_link_libraries(${target} PUBLIC ${AWSSDK_LIBRARIES})
    if(_duckbox_aws_sts_ok)
      target_compile_definitions(${target} PUBLIC DUCKBOX_HAS_STS_ASSUME_ROLE=1)
    endif()
  endif()
  if(APPLE)
    target_link_libraries(${target} PUBLIC
      "-framework CoreFoundation"
      "-framework Security"
      "-framework SystemConfiguration")
  endif()
endfunction()

duckbox_link_core_deps(duckbox_objs)
duckbox_link_core_deps(duckbox_sandbox)
duckbox_link_core_deps(duckbox_sandbox_testing)
duckbox_link_core_deps(duckbox_core)
duckbox_link_core_deps(duckbox_core_testing)
# Objects that #ifdef DUCKBOX_HAS_STS_ASSUME_ROLE need the same define.
if(TARGET aws-cpp-sdk-sts AND TARGET aws-cpp-sdk-identity-management)
  target_compile_definitions(duckbox_objs PUBLIC DUCKBOX_HAS_STS_ASSUME_ROLE=1)
  target_compile_definitions(duckbox_sandbox PUBLIC DUCKBOX_HAS_STS_ASSUME_ROLE=1)
  target_compile_definitions(duckbox_sandbox_testing PUBLIC DUCKBOX_HAS_STS_ASSUME_ROLE=1)
elseif(_duckbox_aws_sts_ok)
  target_compile_definitions(duckbox_objs PUBLIC DUCKBOX_HAS_STS_ASSUME_ROLE=1)
  target_compile_definitions(duckbox_sandbox PUBLIC DUCKBOX_HAS_STS_ASSUME_ROLE=1)
  target_compile_definitions(duckbox_sandbox_testing PUBLIC DUCKBOX_HAS_STS_ASSUME_ROLE=1)
endif()

set(_duckdb_libdir "${DUCKBOX_DEPS}/duckdb/lib")
# DuckDB 2.0 static-lib archives are flattened: libduckdb_static.a plus
# parquet/core_functions/json/icu/autocomplete. Do not link the extra bundled
# extensions (httpfs/fts/inet/tpch/tpcds); those stay INSTALL/LOAD.
set(_duckdb_libs
  duckdb_static
  parquet_extension
  core_functions_extension
  json_extension
  icu_extension
  autocomplete_extension)
# Official macOS static-libs tarball does not include libduckdb_jemalloc.a.
if(EXISTS "${_duckdb_libdir}/libduckdb_jemalloc.a")
  list(APPEND _duckdb_libs duckdb_jemalloc)
endif()

set(_duckdb_link_files)
foreach(_lib ${_duckdb_libs})
  list(APPEND _duckdb_link_files "${_duckdb_libdir}/lib${_lib}.a")
endforeach()

# Capabilities registered via describe + force-load: INSTALL/LOAD provider and
# the builtin HTTP client used to fetch community extensions (nanoarrow).
# --start-group will not pull these unless a symbol is referenced.
set(_duckdb_forced_libs
  "${_duckdb_libdir}/libduckdb_loadable_extensions.a"
  "${_duckdb_libdir}/libduckdb_httplib.a")

function(duckbox_link_duckdb target)
  if(APPLE)
    set(_forced)
    foreach(_lib ${_duckdb_forced_libs})
      list(APPEND _forced "-Wl,-force_load,${_lib}")
    endforeach()
    target_link_libraries(${target} PRIVATE
      ${_duckdb_link_files}
      ${_forced}
      pthread dl)
    target_link_options(${target} PRIVATE "-Wl,-u,_duckbox_ensure_linked_duckdb")
  else()
    target_link_libraries(${target} PRIVATE
      -Wl,--start-group ${_duckdb_link_files} -Wl,--end-group
      -Wl,--whole-archive ${_duckdb_forced_libs} -Wl,--no-whole-archive
      pthread dl)
    target_link_options(${target} PRIVATE "-Wl,-u,duckbox_ensure_linked_duckdb")
  endif()
endfunction()

duckbox_link_duckdb(duckbox_core)
duckbox_link_duckdb(duckbox_core_testing)

add_executable(duckbox server/src/main.cpp)
target_include_directories(duckbox PRIVATE ${DUCKBOX_DEPS}/cli11)
target_link_libraries(duckbox PRIVATE duckbox_core)
duckbox_link_duckdb(duckbox)

function(duckbox_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE duckbox_core_testing)
  duckbox_link_duckdb(${name})
  target_include_directories(${name} PRIVATE
    ${CMAKE_SOURCE_DIR}/test/support
    ${CMAKE_SOURCE_DIR}/test/unit
    ${CMAKE_SOURCE_DIR}/test/integration)
  target_compile_definitions(${name} PRIVATE
    DUCKBOX_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
    DUCKBOX_TESTING)
endfunction()

duckbox_add_test(duckbox_unit_tests
  test/support/check.cpp
  test/unit/main.cpp
  test/unit/auth_test.cpp
  test/unit/tenant_key_test.cpp
  test/unit/spec_loader_test.cpp
  test/unit/validator_test.cpp
  test/unit/init_sql_test.cpp
  test/unit/rewriter_test.cpp
  test/unit/cte_scope_test.cpp
  test/unit/hidden_filter_rewrite_test.cpp
  test/unit/handle_test.cpp
  test/unit/crypto_test.cpp
  test/unit/registry_test.cpp
  test/unit/metrics_test.cpp
  test/unit/s3_test.cpp
  test/unit/lease_test.cpp
  test/unit/membership_test.cpp
  test/unit/connect_deny_test.cpp
  test/unit/trigger_deny_test.cpp
  test/unit/quack_deny_test.cpp
  test/unit/extension_capi_deny_test.cpp
  test/unit/agent_mode_deny_test.cpp
  test/unit/table_function_20_test.cpp
  test/unit/macro_catalog_20_test.cpp
  test/unit/lake_attach_test.cpp)

duckbox_add_test(duckbox_guardrail_tests
  test/support/check.cpp
  test/guardrails/runner.cpp)

duckbox_add_test(duckbox_integration_tests
  test/support/check.cpp
  test/integration/main.cpp
  test/integration/sandbox_exec_test.cpp
  test/integration/cte_exec_test.cpp
  test/integration/cte_flight_test.cpp
  test/integration/hidden_filter_exec_test.cpp
  test/integration/hidden_filter_flight_test.cpp
  test/integration/runtime_test.cpp
  test/integration/s3_registry_test.cpp
  test/integration/auth_flight_test.cpp
  test/integration/bearer_flight_test.cpp
  test/integration/cluster_test.cpp
  test/integration/signal_shutdown_test.cpp
  test/integration/connect_runtime_test.cpp
  test/integration/trigger_runtime_test.cpp
  test/integration/quack_runtime_test.cpp
  test/integration/extension_capi_runtime_test.cpp
  test/integration/agent_mode_runtime_test.cpp
  test/integration/secret_flight_test.cpp)
add_dependencies(duckbox_integration_tests duckbox)
target_compile_definitions(duckbox_integration_tests PRIVATE
  DUCKBOX_BIN_PATH="$<TARGET_FILE:duckbox>")

duckbox_add_test(duckbox_schema_tests
  test/support/check.cpp
  test/schema/main.cpp
  test/schema/type_map_test.cpp
  test/schema/flight_schema_test.cpp
  test/schema/variant_test.cpp)
target_include_directories(duckbox_schema_tests BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/test/schema)

duckbox_add_test(duckbox_s3_credentials_tests
  test/support/check.cpp
  test/unit/s3_credentials_test.cpp)

duckbox_add_test(duckbox_s3_secret_guardrail_tests
  test/support/check.cpp
  test/guardrails/s3_secrets_test.cpp)

duckbox_add_test(duckbox_s3_sts_tests
  test/support/check.cpp
  test/integration/s3_sts_test.cpp)

enable_testing()
add_test(NAME unit COMMAND duckbox_unit_tests)
add_test(NAME guardrails COMMAND duckbox_guardrail_tests)
add_test(NAME integration COMMAND duckbox_integration_tests)
add_test(NAME schema COMMAND duckbox_schema_tests)
add_test(NAME s3_credentials COMMAND duckbox_s3_credentials_tests)
add_test(NAME s3_secret_guardrails COMMAND duckbox_s3_secret_guardrail_tests)
add_test(NAME s3_sts COMMAND duckbox_s3_sts_tests)
set_tests_properties(unit PROPERTIES LABELS "unit")
set_tests_properties(guardrails PROPERTIES LABELS "guardrails")
set_tests_properties(integration PROPERTIES LABELS "integration")
# Also labeled unit so macOS `ctest -L unit|guardrails` runs it.
set_tests_properties(schema PROPERTIES LABELS "schema;unit")
set_tests_properties(s3_credentials PROPERTIES LABELS "unit")
set_tests_properties(s3_secret_guardrails PROPERTIES LABELS "guardrails")
set_tests_properties(s3_sts PROPERTIES LABELS "integration")
