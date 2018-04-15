cmake_minimum_required(VERSION 3.1)
project(TPM2_PK11 LANGUAGES C)
include(${CMAKE_ROOT}/Modules/GNUInstallDirs.cmake)

find_package(PkgConfig REQUIRED)
function(pkg_check_variable _pkg _name)
  string(TOUPPER ${_pkg} _pkg_upper)
  string(TOUPPER ${_name} _name_upper)
  string(REPLACE "-" "_" _pkg_upper ${_pkg_upper})
  string(REPLACE "-" "_" _name_upper ${_name_upper})
  set(_output_name "${_pkg_upper}_${_name_upper}")

  execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=${_name} ${_pkg} OUTPUT_VARIABLE _pkg_result OUTPUT_STRIP_TRAILING_WHITESPACE)
  set("${_output_name}" "${_pkg_result}" CACHE STRING "pkg-config variable ${_name} of ${_pkg}")
endfunction()

pkg_check_modules(P11_KIT REQUIRED p11-kit-1)
pkg_check_variable(p11-kit-1 p11_module_configs)
pkg_check_variable(p11-kit-1 p11_module_path)
pkg_search_module(SAPI REQUIRED sapi tss2-sys)
pkg_check_modules(TCTI_SOCKET tcti-socket)
pkg_check_modules(TCTI_MSSIM tss2-tcti-mssim)
pkg_search_module(TCTI_DEVICE tcti-device tss2-tcti-device)
pkg_search_module(TCTI_TABRMD tcti-tabrmd tss2-tcti-tabrmd)
pkg_check_modules(LIBTASN1 REQUIRED libtasn1)

if(NOT TCTI_SOCKET_FOUND AND NOT TCTI_MSSIM_FOUND AND NOT TCTI_DEVICE_FOUND AND NOT TCTI_TABRMD_FOUND)
  message(FATAL_ERROR "At least one connection type must be enabled")
endif()

find_library(SAPI_LIBRARIES
  NAMES sapi tss2-sys
  HINTS ${SAPI_LIBDIR} ${SAPI_LIBRARY_DIRS}
)

if(TCTI_SOCKET_FOUND)
  find_library(TCTI_SOCKET_LIBRARIES
    NAMES tcti-socket
    HINTS ${TCTI_SOCKET_LIBDIR} ${TCTI_SOCKET_LIBRARY_DIRS}
  )
endif()

if(TCTI_MSSIM_FOUND)
  find_library(TCTI_MSSIM_LIBRARIES
    NAMES tss2-tcti-mssim
    HINTS ${TCTI_MSSIM_LIBDIR} ${TCTI_MSSIM_LIBRARY_DIRS}
  )
endif()

if(TCTI_DEVICE_FOUND)
  find_library(TCTI_DEVICE_LIBRARIES
    NAMES tcti-device tss2-tcti-device
    HINTS ${TCTI_DEVICE_LIBDIR} ${TCTI_DEVICE_LIBRARY_DIRS}
  )
endif()

if(TCTI_TABRMD_FOUND)
  find_library(TCTI_TABRMD_LIBRARIES
    NAMES tcti-tabrmd tss2-tcti-tabrmd
    HINTS ${TCTI_TABRMD_LIBDIR} ${TCTI_TABRMD_LIBRARY_DIRS}
  )
endif()

find_library(P11_KIT_LIBRARIES
  NAMES p11-kit
  HINTS ${P11_KIT_LIBDIR} ${P11_KIT_LIBRARY_DIRS}
)

find_library(LIBTASN1_LIBRARIES
  NAMES tasn1
  HINTS ${LIBTASN1_LIBDIR} ${LIBTASN1_LIBRARY_DIRS}
)

configure_file("tpm2-pk11.module.in" "tpm2-pk11.module")

aux_source_directory(./src SRC_LIST)

add_library(tpm2-pk11 SHARED ${SRC_LIST})
set_property(TARGET tpm2-pk11 PROPERTY C_STANDARD 11)
target_include_directories(tpm2-pk11 PRIVATE ${P11_KIT_INCLUDE_DIRS} ${SAPI_INCLUDE_DIRS} ${TCTI_SOCKET_INCLUDE_DIRS} ${TCTI_MSSIM_INCLUDE_DIRS} ${TCTI_DEVICE_INCLUDE_DIRS} ${TCTI_TABRMD_INCLUDE_DIRS} ${LIBTASN1_INCLUSE_DIRS})
target_link_libraries(tpm2-pk11 ${P11_KIT_LIBRARIES} ${SAPI_LIBRARIES} ${TCTI_SOCKET_LIBRARIES} ${TCTI_MSSIM_LIBRARIES} ${TCTI_DEVICE_LIBRARIES} ${TCTI_TABRMD_LIBRARIES} ${LIBTASN1_LIBRARIES})
if(TCTI_SOCKET_FOUND)
  target_compile_definitions(tpm2-pk11 PUBLIC TCTI_SOCKET_ENABLED=1)
endif()
if(TCTI_MSSIM_FOUND)
  target_compile_definitions(tpm2-pk11 PUBLIC TCTI_MSSIM_ENABLED=1)
endif()
if(TCTI_DEVICE_FOUND)
  target_compile_definitions(tpm2-pk11 PUBLIC TCTI_DEVICE_ENABLED=1)
endif()
if(TCTI_TABRMD_FOUND)
  target_compile_definitions(tpm2-pk11 PUBLIC TCTI_TABRMD_ENABLED=1)
endif()

if (SAPI_VERSION VERSION_LESS "2.0")
  target_compile_definitions(tpm2-pk11 PUBLIC TSS_COMPAT=1)
endif()

install(TARGETS tpm2-pk11 DESTINATION ${P11_KIT_1_P11_MODULE_PATH})
install(FILES ${CMAKE_BINARY_DIR}/tpm2-pk11.module DESTINATION ${P11_KIT_1_P11_MODULE_CONFIGS})
