Cryptography Abstraction Layer
==============================

Rationale
---------

There are several extensions & libraries that provide cryptography primitives
for PHP:

* the legacy `mcrypt <http://php.net/mcrypt>`_ extension
* the `OpenSSL <http://php.net/openssl>`_ extension
* the `libsodium <https://github.com/jedisct1/libsodium-php>`_ extension
* my very own `tomcrypt <https://github.com/fpoirotte/tomcrypt>`_ extension
* and probably others...

Although these extensions all provide roughtly the same features,
the programmatic interface they expose is very different.

This project is comprised of a unified API (this package), which serves
to abstract those differences away, and various packages that provide
implementations for the unified interface (see `implementations`_
for a list of all available implementations).


How to use it?
--------------

First, add a requirement in your own project on either:

* ``fpoirotte/cryptal-implementation`` to let Composer select a compatible
  implementation automatically for your PHP installation.

* Or a specific implementation if you want to precisely control which
  implementation is used.
  Again, see `implementations`_ for a list of available implementations.

Then, whenever you would like to apply some cryptographic operation,
retrieve an instance of the implementation using the following snippet:

..  sourcecode:: php

    <?php

    // One of the CIPHER_* constants from \fpoirotte\Cryptal\CryptoInterface
    $cipher = CIPHER_AES;

    // One of the MODE_* constants from \fpoirotte\Cryptal\CryptoInterface
    $cipher = MODE_CBC;

    $impl = \fpoirotte\Cryptal\CryptoFactory::getImplementation($cipher, mode);

    ?>

Now, use whatever method you need to from the interface.
For example:

..  sourcecode:: php

    <?php

    // Generate an appropriate Initialization Vector
    $iv = openssl_random_pseudo_bytes($impl->getIVSize(), true);

    // Define a secret key of an appropriate size
    // for the cipher we're using.
    // Eg. 16 bytes for AES-128.
    $key = "Use a secret key";

    // The plaintext's length should be a multiple of the cipher's block size.
    // Again, that's 16 bytes for AES.
    // Use $impl->getBlockSize() if necessary to retrieve the block size.
    $plaintext = "Some secret text";
    var_dump(bin2hex($plaintext));

    $ciphertext = $impl->encrypt($iv, $key, $plaintext);
    var_dump(bin2hex($ciphertext));

    $decoded = $impl->decrypt($iv, $key, $ciphertext);
    var_dump(bin2hex($decoded));

    ?>


How to contribute a new implementation?
---------------------------------------

New implementations MUST be delivered as Composer packages.
Each such package MUST:

* Provide a concrete implementation for every interface in this package
* Give the name ``\fpoirotte\Cryptal\Implemenration`` to the entry point
  (the class that implements the ``\fpoirotte\Cryptal\CryptoInterface``
  interface).
* Add ``fpoirotte/cryptal`` to their requirements
* Add ``fpoirotte/cryptal-implementation`` to their provides


.. _implementations:
    https://packagist.org/providers/fpoirotte/cryptal-implementation
