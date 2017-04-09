find_package(PkgConfig REQUIRED)
pkg_check_modules(P11_KIT REQUIRED p11-kit-1)

aux_source_directory(./ TPM2_PK11_SRC_LIST)

add_library(tpm2-pk11 SHARED ${TPM2_PK11_SRC_LIST})
set_property(TARGET tpm2-pk11 PROPERTY C_STANDARD 99)
target_include_directories(tpm2-pk11 PRIVATE ${P11_KIT_INCLUDE_DIRS})
target_link_libraries(tpm2-pk11 ${P11_KIT_LIBRARIES})
