cmake_minimum_required(VERSION 3.1)
project(TPM2_PK11 LANGUAGES C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(P11_KIT REQUIRED p11-kit-1)
pkg_check_modules(SAPI REQUIRED sapi)
pkg_check_modules(TCTI_SOCKET REQUIRED tcti-socket)
pkg_check_modules(TCTI_DEVICE REQUIRED tcti-device)

aux_source_directory(./src SRC_LIST)

add_library(tpm2-pk11 SHARED ${SRC_LIST})
set_property(TARGET tpm2-pk11 PROPERTY C_STANDARD 99)
target_include_directories(tpm2-pk11 PRIVATE ${P11_KIT_INCLUDE_DIRS} ${SAPI_INCLUDE_DIRS} ${TCTI_SOCKET_INCLUDE_DIRS} ${TCTI_DEVICE_INCLUDE_DIRS})
target_link_libraries(tpm2-pk11 ${P11_KIT_LIBRARIES} ${SAPI_LIBRARIES} ${TCTI_SOCKET_LIBRARIES} ${TCTI_DEVICE_LIBRARIES})
