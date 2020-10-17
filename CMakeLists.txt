cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(blake3-provider LANGUAGES C)

find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(blake3 MODULE ${CMAKE_CURRENT_LIST_DIR}/src/blake3.c)
set_target_properties(blake3 PROPERTIES PREFIX "" OUTPUT_NAME "blake3")
target_link_libraries(blake3 ${OPENSSL_CRYPTO_LIBRARY})

add_executable(test_blake3 ${CMAKE_CURRENT_LIST_DIR}/test/test_provider.c)
target_link_libraries(test_blake3 ${OPENSSL_CRYPTO_LIBRARY)})