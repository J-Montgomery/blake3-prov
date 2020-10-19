blake3-prov
======================

This is a BLAKE3 provider implementation for OpenSSL, intended to provide access
to BLAKE3 until the algorithm is standardized and implemented upstream.

Dependencies
========
 - OpenSSL 3.0 or greater
 - CMake 3.10 or greater

Building
========

Create a separate build tree:

    $ mkdir output && cd output
    $ cmake ../ && make

The only currently supported platform is Linux, using GCC or Clang. Other
platforms and compilers may or may not work.

Configuration Flags
-------------------
 - BLAKE3_ENABLE_SSE
    - Set CMake flag to 1 during invocation to enable SSE2 and SSE4.1
    optimziations in BLAKE3. If not set, this option will default to the
    appropriate setting for the host system.

 - BLAKE3_ENABLE_AVX2
    - Set to 1 to enable AVX2 support in BLAKE3. This option defaults to
    enabled.

 - BLAKE3_ENABLE_AVX512
    - Set to 1 to enable AVX512 support in BLAKE3. This option defaults to
    disabled.

 - BLAKE3_ENABLE_NEON
    - Set to 1 to enable NEON support in BLAKE3. This option defaults to
    disabled.

Environment Variables
---------------------

 - OPENSSL_MODULES_DIR
    - If this environment variable is set, the install script will install 
    the provider library to the directory specified.

Running Tests
=============

Tests can be run with CTest:

    $ ctest ..

Installation
============

Run the installation script with:

    $ sudo make install

License
=======
blake3-prov is distributed under an Apache 2.0 license. See [LICENSE](LICENSE) for details.

Attributions
============
The BLAKE3 implementation and test vectors used were provided by the [Blake3](https://github.com/BLAKE3-team/BLAKE3) reference implementation.