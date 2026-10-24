# Optional goose backend for util/strings. Included only when
# DUCKBOX_EXPERIMENTAL_GOOSE=ON. The default build never loads this file.

set(DUCKBOX_GOOSE_VERSION "v2026.3")

function(duckbox_add_goose_strings target)
  set(_goose_root "${DUCKBOX_DEPS}/goose-${DUCKBOX_GOOSE_VERSION}")
  set(_goose_bin "${_goose_root}/goose")
  if(DEFINED ENV{GOOSE} AND EXISTS "$ENV{GOOSE}")
    set(_goose_bin "$ENV{GOOSE}")
  elseif(NOT EXISTS "${_goose_bin}")
    message(STATUS "Fetching goose ${DUCKBOX_GOOSE_VERSION} into ${DUCKBOX_DEPS}")
    execute_process(
      COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/fetch_goose.sh"
      RESULT_VARIABLE _goose_fetch_rv)
    if(NOT _goose_fetch_rv EQUAL 0)
      message(FATAL_ERROR "scripts/fetch_goose.sh failed")
    endif()
  endif()
  if(NOT EXISTS "${_goose_bin}")
    message(FATAL_ERROR "goose compiler not found at ${_goose_bin} (set GOOSE)")
  endif()

  set(_gen_dir "${CMAKE_BINARY_DIR}/generated/goose")
  set(_gen_c "${_gen_dir}/strings_goose.c")
  set(_gen_h "${_gen_dir}/strings_goose.h")
  set(_src "${CMAKE_SOURCE_DIR}/server/src/util/strings.goose")
  file(MAKE_DIRECTORY "${_gen_dir}")

  add_custom_command(
    OUTPUT "${_gen_c}" "${_gen_h}"
    COMMAND "${_goose_bin}" --standalone --header "${_gen_h}" -o "${_gen_c}" "${_src}"
    DEPENDS "${_src}" "${_goose_bin}"
    COMMENT "Generating goose C for util/strings"
    VERBATIM)

  add_library(duckbox_goose_strings STATIC "${_gen_c}")
  set_target_properties(duckbox_goose_strings PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON)
  target_include_directories(duckbox_goose_strings PUBLIC "${_gen_dir}")
  if(NOT WIN32)
    target_link_libraries(duckbox_goose_strings PUBLIC m pthread)
  endif()
  # Goose standalone reserves large data stacks; keep the C quiet.
  if(NOT MSVC)
    target_compile_options(duckbox_goose_strings PRIVATE -Wno-unused-parameter)
  endif()

  target_compile_definitions(${target} PUBLIC DUCKBOX_EXPERIMENTAL_GOOSE=1)
  target_link_libraries(${target} PUBLIC duckbox_goose_strings)
endfunction()
