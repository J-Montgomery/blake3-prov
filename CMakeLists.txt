cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(blake3-provider LANGUAGES C)

enable_testing()

set(TEST_LDFLAGS "-fsanitize=address")

find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(src)
add_subdirectory(test)


