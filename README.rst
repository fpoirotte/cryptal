Cryptography Abstraction Layer
##############################

Rationale
=========

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
==============

First, add a requirement in your own project on either:

* ``fpoirotte/cryptal-implementation`` to let Composer select a compatible
  implementation automatically for your PHP installation.

* Or a specific implementation if you want to precisely control which
  implementation is used.
  Again, see `implementations`_ for a list of available implementations.

The next step depends on the type of operations you would like to do:

*   Cryptal can work in "stream mode", where data in encrypted/decrypted
    on the fly and the processor does not know in advance when the end of
    the data stream will be reached. This mode of operation is adequate
    for network protocols or when manipulating large files that would not
    fit into memory.

*   It can also operate in "one-shot mode", where the encryption/decryption
    processor works on the complete data at once (thus knowing when to end).
    This mode is adequate for encrypting/decrypting strings and small files.

A specific interface is provided for each mode.


Streaming encryption/decryption
-------------------------------

..  warning::

    When using streaming encryption/decryption, the library relies mostly
    on PHP code to handle the process. The underlying library is only used
    to provide the cryptographic primitives for the selected cipher
    in `ECB <https://en.wikipedia.org/wiki/Electronic_codebook>`_ mode.

    This hurts performance a bit, but more importantly, this may diminish
    your application's security, because some values (keys, IVs, etc.)
    cannot be safely erased from memory and may linger there even after
    you are done processing the data.

    If you are concerned about these issues, to not use streaming
    encryption/decryption.


For convenience, Cryptal provides stream wrappers to easily encrypt/decrypt
data on the fly.

..  note::

    A stream context is required when using this interface,
    to pass all necessary settings to the library.

    See the section on `Encryption/decryption contexts`_ for more information.


Encryption
~~~~~~~~~~

Encrypting some data is easy:

..  sourcecode:: php

    <?php
        // Initialize the library (can be called multiple times)
        \fpoirotte\Cryptal\init();

        // Create an encryption context (see below)
        $ctx = stream_context_create(
            array(
                'cryptal' => array(
                    // Secret key.
                    // Size must be compatible with the cipher's expectations.
                    'key'   => '0123456789abcdef',

                    // Initialization Vector.
                    // Size must be compatible with the cipher's expectations.
                    'IV'    => 'abcdef0123456789',
                )
            )
        );

        $plaintext = "Some secret message we want to transmit securely";

        // Open a new encryption stream, using the AES-128 cipher in CTR mode.
        $encrypt = fopen("cryptal.encrypt://MODE_CTR/CIPHER_AES_128", 'w+', false, $ctx);

        // Feed the wrapper with the data to encrypt.
        fwrite($encrypt, $plaintext);

        // The encrypted data can be retrieved using fread().
        // Make sure the $length argument is big enough to hold
        // data that's at least 2 times the cipher's block size.
        //
        // fread() will return an empty string if there is not enough
        // data in the buffer, a block of encrypted data, or false
        // on error (eg. when the given $length is too small).
        while ($data = fread($encrypt, 1024)) {
            // Do something with the data...
        }

        // Notify the wrapper that the end of the data has been reached.
        fflush($encrypt);

        // After fflush() has been called, you should keep reading
        // from the stream until no more data can be retrieved.
        while ($data = fread($encrypt, 1024)) {
            // Do something with the data...
        }

        // After that, the wrapper will be unusable and a new one
        // must be created if another set of data must be processed.
    ?>


Decryption
~~~~~~~~~~

Decryption works pretty must the same way:

..  sourcecode:: php

    <?php
        // Initialize the library (can be called multiple times)
        \fpoirotte\Cryptal\init();

        // Create a decryption context (see below)
        $ctx = stream_context_create(
            array(
                'cryptal' => array(
                    // Secret key.
                    // Size must be compatible with the cipher's expectations.
                    'key'   => '0123456789abcdef',

                    // Initialization Vector.
                    // Size must be compatible with the cipher's expectations.
                    'IV'    => 'abcdef0123456789',
                )
            )
        );

        // Open a new decryption stream, using the AES-128 cipher in CTR mode.
        $decrypt = fopen("cryptal.decrypt://MODE_CTR/CIPHER_AES_128", 'w+', false, $ctx);

        // Feed the wrapper with the data to decrypt.
        fwrite($decrypt, $ciphertext);

        // Just like for encryption, decrypted data can be retrieved
        // using fread().
        $plaintext = '';
        while ($data = fread($decrypt, 1024)) {
            // Do something with the data...
            $plaintext .= $data;
        }

        // Notify the wrapper that the end of the data has been reached.
        fflush($decrypt);

        // After fflush() has been called, you should keep reading
        // from the stream until no more data can be retrieved.
        while ($data = fread($decrypt, 1024)) {
            // Do something with the data...
            $plaintext .= $data;
        }

        // After that, the wrapper will be unusable and a new one
        // must be created if another set of data must be processed.
    ?>


Encryption/decryption contexts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Streaming encryption/decryption uses a stream context to pass several
settings to the wrapper.

The following table lists available options:

..  list-table:: Available options in encryption/decryption contexts
    :header-rows: 1

    *   - Name
        - Expected type
        - Description

    *   - ``AAD``
        - string
        - Additional Authenticated Data when using `Authenticated Encryption <https://en.wikipedia.org/wiki/Authenticated_encryption>`_

    *   - ``IV``
        - string
        - Initialization Vector for the cipher

    *   - ``key``
        - string
        - Symmetric key to use for encryption/decryption

    *   - ``padding``
        - Instance of ``\fpoirotte\Cryptal\PaddingInterface``
        - Padding scheme to use

    *   - ``tagLength``
        - integer
        - Desired tag length when using `Authenticated Encryption <https://en.wikipedia.org/wiki/Authenticated_encryption>`_


To set an option, use ``stream_context_set_option()``:

..  sourcecode::

    <?php
        stream_context_set_option($stream_or_context, 'cryptal', $option, $value);
    ?>


To retrieve the current value for an option,
use ``stream_context_get_options()``:

..  sourcecode::

    <?php
        $options = stream_context_get_options($stream_or_context);
        $padding = $options['cryptal']['padding'];
        echo "Padding scheme in use: " . get_class($padding) . PHP_EOL;
    ?>


One-shot encryption/decryption
------------------------------

Then, whenever you would like to apply some cryptographic operation,
retrieve an instance of the implementation using the following snippet:

..  sourcecode:: php

    <?php

    use \fpoirotte\Cryptal\Implementation;
    use \fpoirotte\Cryptal\CryptoInterface;

    // Initialize the library (can be called multiple times)
    \fpoirotte\Cryptal\init();

    // Retrieve an instance of the implementation.
    // Use the CIPHER_* & MODE_* constants from the CryptoInterface
    // to indicate the cipher & mode to use, respectively.
    $impl = new Implementation(CryptoInterface::CIPHER_AES, CryptoInterface::MODE_CBC);

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


Padding
-------

By default, the streaming interface pads data using the PKCS#7 scheme.
If you need to use another padding scheme, you can easily swap the default
for an alternate implementation. Just set the ``padding`` context option
to an instance of the scheme to use before opening the stream:

..  sourcecode::

    <?php

        use fpoirotte\Cryptal\Padding\AnsiX923;

        $ctx = stream_context_create(
            array(
                'cryptal' => array(
                    'key'       => '0123456789abcdef',
                    'IV'        => 'abcdef0123456789',

                    // Use the ANSI X.923 padding scheme instead of PKCS#7.
                    'padding'   => new AnsiX923,
                )
            )
        );

        $encrypt = fopen("cryptal.encrypt://MODE_CTR/CIPHER_AES_128", 'w+', false, $ctx);

        // ...
    ?>

For one-shot encryption/decryption, @TODO.


How to contribute a new implementation?
=======================================

New implementations MUST be delivered as Composer packages.
Each such package MUST:

* Provide a concrete implementation for the ``\fpoirotte\Cryptal\CryptoInterface``
  interface and name that class  ``\fpoirotte\Cryptal\Implementation``.
* Add ``fpoirotte/cryptal`` to their requirements
* Add ``fpoirotte/cryptal-implementation`` to their provides

See https://github.com/fpoirotte/cryptal-mcrypt for an example of how
this is done.


.. _implementations:
    https://packagist.org/providers/fpoirotte/cryptal-implementation
