blake3-prov
======================

This is a BLAKE3 provider implementation for OpenSSL, intended to provide access to the BLAKE3 digest until the algorithm is standardized and implemented upstream.

Dependencies
========
 - OpenSSL 3.0 or greater
 - CMake 3.0 or greater


Building
========

Create a separate build tree:

    $ mkdir output && cd output
    $ cmake ../ && make

Running Tests
=============

..

Installation
============

Run the installation script with:

    $ sudo make install

You can set the installation directory for the modules by setting the OPENSSL_MODULES_DIR environment variable before running CMake.

License
=======
blake3-prov is distributed under an Apache 2.0 license. See `LICENSE`_ for details.

.. _`LICENSE`: LICENSE

Attributions
============
The [Blake3](https://github.com/BLAKE3-team/BLAKE3) team provided the digest implementation here.

Useful examples of the OpenSSL 3.0+ provider API provided by [provider-corner](https://github.com/provider-corner).