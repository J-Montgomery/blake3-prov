cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(blake3-provider LANGUAGES C)

function(find_openssl_modules_dir DIR_PATH)
    find_library(OPENSSL_FIPS_INSTALL_PATH NAMES "fips.so" PATH_SUFFIXES ossl-modules)
    get_filename_component(PROVIDER_INSTALL_DIR ${OPENSSL_FIPS_INSTALL_PATH} DIRECTORY)
    set(${DIR_PATH} ${PROVIDER_INSTALL_DIR} PARENT_SCOPE)
endfunction()

set(TEST_LDFLAGS "-fsanitize=address")

find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(blake3 MODULE ${CMAKE_CURRENT_LIST_DIR}/src/blake3.c)
set_target_properties(blake3 PROPERTIES PREFIX "" OUTPUT_NAME "blake3")
target_link_libraries(blake3 ${OPENSSL_CRYPTO_LIBRARY})

# Install provider into OpenSSL modules directory if available
find_openssl_modules_dir(OPENSSL_PROV_INSTALL_DIR)
if(OPENSSL_PROV_INSTALL_DIR)
    install(TARGETS blake3 DESTINATION ${OPENSSL_PROV_INSTALL_DIR})
else()
    # Use OPENSSL_MODULES env var when running executables manually instead
    message(WARNING "Unable to find OpenSSL modules directory for provider installation")
    set(OUTPUT_MODULES_DIR ${CMAKE_BINARY_DIR})
endif()

add_executable(test_blake3 ${CMAKE_CURRENT_LIST_DIR}/test/test_provider.c)
target_link_libraries(test_blake3 ${OPENSSL_CRYPTO_LIBRARY} ${TEST_LDFLAGS})


