Installation
============

Cryptal relies on `Composer <https://getcomposer.org/>`_ for its installation.
It also uses `plugins <https://packagist.org/providers/fpoirotte/cryptal-implementation>`_
to provide implementations for the various algorithms.

Cryptal can be installed by itself using the following command:

..  sourcecode:: bash

    $ php composer.php require fpoirotte/cryptal

However, the core package only provides a few algorithms using mostly PHP code.
Therefore, you will usually want to install additional plugins to get access
to more algorithms.

Which plugin to install depends on the algorithms you need to use and whether
you're willing to sacrifice a bit of speed and security to get additionnal
algorithms.

Cryptal supports 3 types of implementations:

*   Assembly code, which provides maximum speed and is usually secure.
*   Compiled code, which can be a tiny bit slower, but is often more secure.
*   PHP code, which is slower and less secure, but provides support for some
    niche algorithms.

Choosing the plugin(s) to install
---------------------------------

The following tables list the algorithms provided by each plugin, with their
implementation type. "Core" means the algorithm is provided by the Cryptal
package itself and does not require any additional plugin to work.

Please note that these lists are only given as an indication of what the
underlying library supports.
The actual supported algorithms may vary due to differing compilation options
or differing versions being used.

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
        -   Hash
        -   PHP-Crypto

    *   -   TripleDES (3DES)
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   AES-128
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   AES-192
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   AES-256
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   compiled [#]_
        -   n/a
        -   compiled

    *   -   Blowfish
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   Camellia-128
        -   PHP code
        -   n/a
        -   compiled
        -   n/a
        -   n/a
        -   n/a
        -   compiled

    *   -   Camellia-192
        -   PHP code
        -   n/a
        -   compiled
        -   n/a
        -   n/a
        -   n/a
        -   compiled

    *   -   Camellia-256
        -   PHP code
        -   n/a
        -   compiled
        -   n/a
        -   n/a
        -   n/a
        -   compiled

    *   -   CAST5
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   ChaCha20 (IETF variant)
        -   PHP code
        -   n/a
        -   n/a
        -   n/a
        -   compiled
        -   n/a
        -   n/a

    *   -   ChaCha20 (OpenSSH variant)
        -   PHP code
        -   n/a
        -   n/a
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
        -   n/a
        -   compiled

    *   -   RC2
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   RC4
        -   n/a
        -   compiled
        -   compiled
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   SEED
        -   n/a
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   Twofish
        -   n/a
        -   compiled
        -   n/a
        -   compiled
        -   n/a
        -   n/a
        -   compiled

..  [#] libsodium only supports AES-256 in GCM mode.
        Also, this cipher/mode combination is not available
        unless the processor of the machine running the code
        has support for the AES-NI instruction set.


Hashing algorithms
~~~~~~~~~~~~~~~~~~

..  list-table::
    :header-rows: 1
    :stub-columns: 1

    *   -   Algorithm
        -   Core
        -   Mcrypt
        -   OpenSSL
        -   LibTomCrypt
        -   LibSodium
        -   Hash
        -   PHP-Crypto

    *   -   CRC32
        -   compiled
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   compiled
        -   n/a

    *   -   MD2
        -   n/a
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   MD4
        -   n/a
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   MD5
        -   compiled
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   RIPEMD160
        -   n/a
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   SHA1
        -   compiled
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   SHA224
        -   n/a
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   SHA256
        -   n/a
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   SHA384
        -   n/a
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   SHA512
        -   n/a
        -   n/a
        -   compiled
        -   compiled
        -   n/a
        -   compiled
        -   compiled

Message authentication algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

..  list-table::
    :header-rows: 1
    :stub-columns: 1

    *   -   Algorithm
        -   Core
        -   Mcrypt
        -   OpenSSL
        -   LibTomCrypt
        -   LibSodium
        -   Hash
        -   PHP-Crypto

    *   -   CMAC
        -   PHP code
        -   n/a
        -   n/a
        -   compiled
        -   n/a
        -   n/a
        -   compiled

    *   -   HMAC
        -   n/a
        -   n/a
        -   n/a
        -   compiled
        -   n/a
        -   compiled
        -   compiled

    *   -   Poly1305
        -   PHP code
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   n/a

    *   -   UMAC-32
        -   PHP code
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   n/a

    *   -   UMAC-64
        -   PHP code
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   n/a

    *   -   UMAC-92
        -   PHP code
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   n/a
        -   n/a

    *   -   UMAC-128
        -   PHP code
        -   n/a
        -   n/a
        -   compiled
        -   n/a
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
    $
    $ # Plugin based on the PHP-Crypto extension
    $ php composer.php require fpoirotte/cryptal-php-crypto

.. vim: ts=4 et
