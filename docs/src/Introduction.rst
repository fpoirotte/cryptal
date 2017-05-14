Introduction
============

There are several extensions & libraries that provide cryptography primitives
for PHP:

* the legacy `mcrypt <http://php.net/mcrypt>`_ extension
* the `OpenSSL <http://php.net/openssl>`_ extension
* the `libsodium <https://github.com/jedisct1/libsodium-php>`_ extension
* my very own `tomcrypt <https://github.com/fpoirotte/tomcrypt>`_ extension
* and probably others...

Although these extensions all provide roughtly the same features,
the programmatic interface they expose is very different.

Also, very few of those extensions support on-the-fly encryption/decryption.

Cryptal was created to work around these issues by providing a unified
interface & transparent support for on-the-fly encryption/decryption
using stream wrappers.

.. vim: ts=4 et

