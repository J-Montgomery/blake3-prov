function(find_openssl_modules_dir DIR_PATH)
    if(DEFINED ENV{OPENSSL_MODULES_DIR})
        get_filename_component(PROVIDER_INSTALL_DIR $ENV{OPENSSL_MODULES_DIR} ABSOLUTE)
    else()
        find_library(OPENSSL_FIPS_INSTALL_PATH NAMES "fips.so" PATH_SUFFIXES ossl-modules)
        get_filename_component(PROVIDER_INSTALL_DIR ${OPENSSL_FIPS_INSTALL_PATH} DIRECTORY)
    endif()

    set(${DIR_PATH} ${PROVIDER_INSTALL_DIR} PARENT_SCOPE)
endfunction()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR})

# Create the provider target
add_library(blake3 MODULE blake3.c)
set_target_properties(blake3 PROPERTIES PREFIX ""
                             OUTPUT_NAME "blake3")
target_link_libraries(blake3 ${OPENSSL_CRYPTO_LIBRARY})

# Install provider into OpenSSL modules directory if available
find_openssl_modules_dir(OPENSSL_PROV_INSTALL_DIR)
if(OPENSSL_PROV_INSTALL_DIR)
    install(TARGETS blake3 DESTINATION ${OPENSSL_PROV_INSTALL_DIR})
else()
    # Use OPENSSL_MODULES env var when running executables manually instead
    message(WARNING "Unable to find OpenSSL modules directory for provider installation")
endif()