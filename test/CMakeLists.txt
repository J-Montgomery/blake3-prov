function(create_test_case TEST_NAME)
    target_link_libraries(${TEST_NAME} ${OPENSSL_CRYPTO_LIBRARY} ${TEST_LDFLAGS})

    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    set_tests_properties(${TEST_NAME}
        PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}")
endfunction()

add_executable(test_fetch test_fetch.c)
create_test_case("test_fetch")

add_executable(test_digest_simple test_digest_simple.c)
create_test_case("test_digest_simple")