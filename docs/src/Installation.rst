Installation
============

Cryptal relies on `Composer <https://getcomposer.org/>`_ for its installation.
It also uses `plugins <https://packagist.org/providers/fpoirotte/cryptal-implementation>`_
to provide implementations for the various algorithms

Which plugin to install depends on the algorithms you need to use and whether
you're willing to sacrifice a bit of speed and security to get additionnal
algorithms.

Cryptal supports 3 types of implementations:

*   Assembly-based code, which provides maximum speed and is usually secure.
*   Compiled code, which is usually a tiny bit slower, but often more secure
    too.
*   PHP code, which is slower and less secure, but provides support for niche
    algorithms.

Choosing the plugin(s) to install
---------------------------------

The following tables list the algorithms provided by each plugin, with their
implementation type. "Core" means the algorithm is provided by the Cryptal
package itself and does not require any additional plugin to work.

Cipher algorithms
~~~~~~~~~~~~~~~~~

..  list-table::
    :header-rows: 1
    :stub-columns: 1

    *   -   Algorithm
        -   Core
        -   Mcrypt
        -   OpenSSL
        -   LibTomCrypt
        -   LibSodium

    *   -   TripleDES (3DES)
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a

    *   -   AES-128
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   compiled (CTR mode only)

    *   -   AES-192
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a

    *   -   AES-256
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a

    *   -   Blowfish
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a

    *   -   Camellia-128
        -   PHP code
        -   n/a
        -   compiled
        -   n/a
        -   n/a

    *   -   Camellia-192
        -   PHP code
        -   n/a
        -   compiled
        -   n/a
        -   n/a

    *   -   Camellia-256
        -   PHP code
        -   n/a
        -   compiled
        -   n/a
        -   n/a

    *   -   CAST5
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a

    *   -   ChaCha20 (IETF variant)
        -   PHP code
        -   n/a
        -   n/a
        -   n/a
        -   compiled

    *   -   ChaCha20 (OpenSSH variant)
        -   PHP code
        -   n/a
        -   n/a
        -   n/a
        -   n/a

    *   -   DES
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a

    *   -   RC2
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a

    *   -   RC4
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a

    *   -   SEED
        -   n/a
        -   n/a
        -   n/a
        -   compiled
        -   n/a

    *   -   Twofish
        -   n/a
        -   compiled
        -   n/a
        -   compiled
        -   n/a

Hashing algorithms
~~~~~~~~~~~~~~~~~~

..  list-table::
    :header-rows: 1
    :stub-columns: 1

    *   -   Algorithm
        -   Core
        -   OpenSSL
        -   LibTomCrypt
        -   LibSodium
        -   Hash

    *   -   CRC32
        -   compiled
        -   n/a
        -   n/a
        -   n/a
        -   compiled

    *   -   MD2
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled

    *   -   MD4
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled

    *   -   MD5
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   compiled

    *   -   RIPEMD160
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled

    *   -   SHA1
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   compiled

    *   -   SHA224
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled

    *   -   SHA256
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   compiled

    *   -   SHA384
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled

    *   -   SHA512
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   compiled

Message authentication algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

..  list-table::
    :header-rows: 1
    :stub-columns: 1

    *   -   Algorithm
        -   Core
        -   LibTomCrypt
        -   LibSodium
        -   Hash

    *   -   CMAC
        -   PHP code
        -   compiled
        -   n/a
        -   n/a

    *   -   HMAC
        -   n/a
        -   compiled
        -   compiled (SHA-256 or SHA-512 only)
        -   compiled

    *   -   Poly1305
        -   PHP code
        -   n/a
        -   n/a
        -   n/a

    *   -   UMAC-32
        -   PHP code
        -   n/a
        -   n/a
        -   n/a

    *   -   UMAC-64
        -   PHP code
        -   n/a
        -   n/a
        -   n/a

    *   -   UMAC-92
        -   PHP code
        -   n/a
        -   n/a
        -   n/a

    *   -   UMAC-128
        -   PHP code
        -   compiled
        -   n/a
        -   n/a


Installing the plugins
----------------------

Once you have determined the algorithms you are going to use and the plugins
providing these algorithms that you want to use, execute the following commands
to install the appropriate plugins:

..  sourcecode:: bash

    $ # Plugin based on the old Mcrypt PHP extension (PHP <= 7.1)
    $ php composer.php require fpoirotte/cryptal-mcrypt
    $
    $ # Plugin based on the OpenSSL PHP extension
    $ php composer.php require fpoirotte/cryptal-openssl
    $
    $ # Plugin based on the LibTomCrypt PHP extension
    $ php composer.php require fpoirotte/cryptal-tomcrypt
    $
    $ # Plugin based on the new LibSodium PHP extension (PHP >= 7.2)
    $ php composer.php require fpoirotte/cryptal-sodium
    $
    $ # Plugin based on the Hash PHP extension
    $ php composer.php require fpoirotte/cryptal-hash

.. vim: ts=4 et
