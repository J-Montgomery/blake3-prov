enable_language(C ASM)

# We only support native compilers to simplify feature selection

set(BLAKE3_COMPILE_OPTS "-O3" "-march=native" "-fPIC")

# The only relevant flag CMake exposes here is SSE2
cmake_host_system_information(RESULT BLAKE3_ENABLE_SSE QUERY HAS_SSE2)

# For everything else, these are good defaults with the current marketshare
set(BLAKE3_ENABLE_AVX2 1)
set(BLAKE3_ENABLE_AVX512 0)
set(BLAKE3_ENABLE_NEON 0)

set(BLAKE3_SOURCES
    blake3.c
    blake3_dispatch.c
    blake3_portable.c
)

set(BLAKE3_HEADERS
    blake3.h
    blake3_impl.h
)


if(BLAKE3_ENABLE_SSE)
    set(BLAKE3_SOURCES ${BLAKE3_SOURCES}
        blake3_sse2.c
        blake3_sse41.c
        blake3_sse2_x86-64_unix.S
        blake3_sse41_x86-64_unix.S
    )
else()
    add_definitions(-DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41)
endif()

if(BLAKE3_ENABLE_AVX2)
    set(BLAKE3_SOURCES ${BLAKE3_SOURCES} 
        blake3_avx2.c
        blake3_avx2_x86-64_unix.S
    )
else()
    add_definitions(-DBLAKE3_NO_AVX2)
endif()

if(BLAKE3_ENABLE_AVX512)
    set(BLAKE3_SOURCES ${BLAKE3_SOURCES} 
        blake3_avx512.c
        blake3_avx512_x86-64_unix.S
    )
else()
    add_definitions(-DBLAKE3_NO_AVX512)
endif()

if(BLAKE3_ENABLE_NEON)
    set(BLAKE3_SOURCES ${BLAKE3_SOURCES} blake3_neon.c)
    add_definitions(-DBLAKE3_USE_NEON)
endif()

add_compile_options(${BLAKE3_COMPILE_OPTS})
add_library(blake3-algo STATIC ${BLAKE3_SOURCES})
