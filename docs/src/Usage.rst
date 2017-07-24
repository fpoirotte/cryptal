Usage
#####

Cryptal provides support for the following features:

*   Encryption/decryption
*   Hashes (also known as message digests)
*   Message Authentication Codes

For each feature, two sets of interfaces are provided:

*   PHP streams, which hide the complexity of the operations
    and provide transparent support for the features.

    This mode of operation is usually adequate for network protocols
    or when manipulating large files that would not fit into memory.

*   Regular PHP interfaces that describe available operations, as well
    as a central ``Registry`` to help look up for an actual implementation
    of some algorithm.

    This mode is usually adequate when working with in-memory strings
    and small files.

The rest of this document describes the interfaces available for each feature.

..  contents::
    :local:


Encryption/decryption
=====================

Using streams
-------------

..  warning::

    When using the stream mode, the library relies mostly on PHP code
    to handle encryption/decryption. The underlying library is only used
    to provide the cryptographic primitives for the selected cipher
    in `ECB <https://en.wikipedia.org/wiki/Electronic_codebook>`_ mode.

    This hurts performance a bit, but more importantly, this may diminish
    your application's security, because some values (keys, IVs, etc.)
    cannot be safely erased from memory and may linger there even after
    you are done processing the data.

    If you are concerned about these issues, do not use these streams.

..  note::

    A stream context is required when using this interface,
    to pass all necessary settings to the library.

    See the section on `Encryption/decryption contexts`_ for more information.


Encryption
~~~~~~~~~~

Encrypting some data is easy:

..  sourcecode:: inline-php

    // Initialize the library
    \fpoirotte\Cryptal::init();

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
    // See fpoirotte\Cryptal\CipherEnum and fpoirotte\Cryptal\ModeEnum
    // for a list of valid ciphers/modes.
    $encrypt = fopen("cryptal.encrypt://MODE_CTR/CIPHER_AES_128", 'w+', false, $ctx);

    // Feed the stream with data to encrypt.
    fwrite($encrypt, $plaintext);

    // The encrypted data can be retrieved using fread().
    // Make sure the $length argument is at least twice
    // the cipher's block size.
    //
    // fread() will return an empty string if there is not enough
    // data in the buffer, a block of encrypted data, or false
    // on error (eg. when the given $length is too small).
    while ($data = fread($encrypt, 1024)) {
        // Do something with the data...
    }

    // Notify the stream that the end of the data has been reached.
    fflush($encrypt);

    // After fflush() has been called, you should keep reading
    // from the stream until no more data can be retrieved.
    while ($data = fread($encrypt, 1024)) {
        // Do something with the data...
    }

    // After that, the stream will be unusable and a new one
    // must be created if further data must be processed.


Here's another example, this time using Authenticated Encryption with
Associated Data (AEAD):

..  sourcecode:: inline-php

    @TODO


Decryption
~~~~~~~~~~

Decryption works the same way. Just substitute ``cryptal.decrypt`` in place
of ``cryptal.encrypt`` when creating the stream.

When using Authenticated Encryption, @TODO


Encryption/decryption contexts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A stream context is needed to configure the encryption/decryption process.

The following table lists available options:

..  list-table:: Available options in encryption/decryption contexts
    :widths: 10 35 55
    :header-rows: 1

    *   - Name
        - Expected type
        - Description

    *   - ``allowUnsafe``
        - boolean
        - Whether userland PHP implementations may be used or not.

          While those implementations add support for some rarely used
          algorithms, they are usually way slower than implementations
          based on PHP extensions.

          Also, those implementations are considered unsafe because they cannot
          protect the application from certain classes of attacks like
          PHP extensions usually do (eg. timing attacks).

          Last but not least, when using those implementations, secret values
          may reside in memory for longer than is actually necessary
          (possibly even longer than the program's actual execution time),
          making them vulnerable to memory forensic techniques and such.

    *   - ``data``
        - string
        - Additional Data to authenticate when using `Authenticated Encryption
          <https://en.wikipedia.org/wiki/Authenticated_encryption>`_

    *   - ``IV``
        - string
        - Initialization Vector for the cipher

    *   - ``key``
        - string
        - Symmetric key to use for encryption/decryption

    *   - ``padding``
        - Instance of ``\fpoirotte\Cryptal\PaddingInterface``
        - Padding scheme to use (defaults to no padding)

    *   - ``tag``
        - string
        - Authentication tag for the current block. This value is set by the
          stream wrapper during encryption of a block. It should be set manually
          when decrypting, before passing a block to decrypt to the stream
          wrapper.

    *   - ``tagLength``
        - integer
        - Desired tag length (in bytes) when using `Authenticated Encryption
          <https://en.wikipedia.org/wiki/Authenticated_encryption>`_.
          Defaults to 16 bytes (128 bits). Only used during encryption,
          as it can be deduced from the ``tag``'s actual length when decrypting.


To set an option, use ``stream_context_set_option()``:

..  sourcecode:: inline-php

    stream_context_set_option($stream_or_context, 'cryptal', $option, $value);


To retrieve the current value for an option,
use ``stream_context_get_options()``:

..  sourcecode:: inline-php

    $options = stream_context_get_options($stream_or_context);
    $padding = $options['cryptal']['padding'];
    echo "Padding scheme in use: " . get_class($padding) . PHP_EOL;

Padding
~~~~~~~

By default, no padding is applied (ie. the padding scheme is set to
an instance of ``fpoirotte\Cryptal\Padding\None``) when using streams.

If you need to use another padding scheme, you can easily swap the default
for an alternate implementation. Just set the ``padding`` context option
to an instance of the padding scheme to use before opening the stream:

..  sourcecode:: inline-php

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
    // Do something with the stream...


Using the registry
------------------

The following snippet shows how to retrieve an implementation
of the AES cipher in ECB mode for encryption/decryption:

..  sourcecode:: inline-php

    use \fpoirotte\Cryptal\Registry;
    use \fpoirotte\Cryptal\Padding\None;
    use \fpoirotte\Cryptal\CipherEnum;
    use \fpoirotte\Cryptal\ModeEnum;

    // Initialize the library
    \fpoirotte\Cryptal::init();

    // Retrieve an implementation for the chosen cipher & mode.
    // See fpoirotte\Cryptal\CipherEnum and fpoirotte\Cryptal\ModeEnum
    // for a list of valid ciphers/modes.
    $impl = Registry::buildCipher(
        CipherEnum::CIPHER_AES_128(),   // Cipher to use
        ModeEnum::MODE_ECB(),           // Mode of operations
        new None(),                     // Padding scheme
        '0123456789abcdef'              // Secret key
        0,                              // Desired tag length (AEAD-only)
        true                            // Whether using plain PHP code
                                        // is okay (less secure/slower)
    );

    // Generate an appropriate Initialization Vector
    $iv = 'abcdef0123456789';

    // Since no padding was used in this example, the plaintext's length
    // must be a multiple of the cipher's block size. That's 16 bytes for AES.
    // Use $impl->getBlockSize() if necessary to retrieve the block size.
    $plaintext = "Some secret text";
    var_dump(bin2hex($plaintext));

    // Encrypt the data
    $ciphertext = $impl->encrypt($iv, $plaintext);
    var_dump(bin2hex($ciphertext));

    // Decryption is just as easy
    $decoded = $impl->decrypt($iv, $ciphertext);
    var_dump(bin2hex($decoded));


Here's another example, this time using Authenticated Encryption with
Associated Data (AEAD):

..  sourcecode:: inline-php

    @TODO


Hashes (message digests)
========================

Using streams
-------------

Hashing data using streams is really easy. For example, to obtain an MD5
message digest for a file (similar to what the PHP ``md5_file()`` function
returns), the following snippet can be used:

..  sourcecode:: inline-php

    // Initialize the library
    \fpoirotte\Cryptal::init();

    // Open the hashing stream & a regular file stream.
    $hashStream = fopen("cryptal.hash://HASH_MD5", 'w+b');
    $fileStream = fopen("/path/to/some.data", "rb");

    // Pass data from the file to the hashing stream.
    stream_copy_to_stream($fileStream, $hashStream);

    // Read the resulting message digest (returned in raw form).
    // The MD5 algorithm produces a 128-bit hash (16 bytes).
    $hash = fread($hashStream, 16);

Using the registry
------------------

Hashing data using the registry is easy too:

..  sourcecode:: inline-php

    use \fpoirotte\Cryptal\Registry;
    use \fpoirotte\Cryptal\HashEnum;

    // Initialize the library
    \fpoirotte\Cryptal::init();

    // Grab an instance of the hash implementation.
    // The last argument indicates whether implementations based on
    // userland PHP code can be returned too.
    // By default, they are not because they are usually slower and
    // more prone to timing attacks.
    $hasher = Registry;:buildHash(HashEnum::HASH_MD5(), true);

    // Pass the data to hash to the implementation.
    $hasher->update(file_get_contents("/path/to/some.data"));

    // Retrieve the resulting hash.
    // The argument given to finish() decides whether the hash
    // should be returned in raw binary form (true) or not (false).
    $hash = $hasher->finish(true);


Message Authentication Codes (MAC)
==================================

Compared to the previous features, message authentication codes can be a bit
tricky to deal with. First, they actually require 2 algorithms to work:

*   One algorithm to process the input data (to compute intermediate values),
    called the "inner algorithm" hereafter.

*   One algorithm to compute the final output (a message authentication code,
    also know as a tag), called the "outer algorithm" in the rest of this
    section.

The algorithms' names are usually combined to obtain a more descriptive (and
unique) name for the whole construct. So for example, "HMAC-MD5" is often used
to refer to the HMAC outer algorithm applied to the MD5 hashing algorithm.

But it gets trickier: the type of the first algorithm depends on the second one.
Some "outer algorithms" (eg. HMAC) expect a hashing algorithm as their
"inner algorithm".
Some (eg. CMAC & UMAC) expect a cipher algorithm as their "inner algorithm".
And finally, some (eg. Poly1305) do not use an inner algorithm at all.
Some "outer algorithms" also impose further limitations on the "inner algorithm"
such as restrictions on the cipher's block size for cipher-based
message authentication codes.

Last but not least, every combination of algorithms requires a secret key,
known only by the two parties trying to prevent any message tampering.
A few algorithms also require what's known as a "nonce", to make the output
less predictable.

Before computing any MAC, we suggest that you get some documentation first
on whatever algorithm you are planning to use to know its requirements.

Using streams
-------------

To compute a MAC using the stream interface, just use code similar to this one:

..  sourcecode:: inline-php

    // Initialize the library
    \fpoirotte\Cryptal::init();

    // Create a MAC context, holding the secret key
    $ctx = stream_context_create(
        array(
            'cryptal' => array(
                // Secret key.
                // Size must be compatible with the algorithms used.
                'key'   => '0123456789abcdef',
            )
        )
    );

    // Open the MAC stream & a regular file stream.
    $macGiver   = fopen("cryptal.mac://MAC_HMAC/HASH_MD5", 'w+b', false, $ctx);
    $fileStream = fopen("/path/to/some.data", "rb");

    // Pass data from the file to the MAC stream.
    stream_copy_to_stream($fileStream, $macGiver);

    // Retrieve the Message Authentication Code in raw binary form.
    // The HMAC-MD5 algorithm produces a 128-bit hash (16 bytes).
    $hash = fread($macGiver, 16);

Using the registry
------------------

Computing a MAC using the registry is very similar to hashing:

..  sourcecode:: inline-php

    use \fpoirotte\Cryptal\Registry;
    use \fpoirotte\Cryptal\MacEnum;
    use \fpoirotte\Cryptal\HashEnum;

    // Initialize the library
    \fpoirotte\Cryptal::init();

    // Grab an instance of the MAC implementation.
    // The last argument indicates whether implementations based on
    // userland PHP code can be returned too.
    // By default, they are not because they are usually slower and
    // more prone to timing attacks.
    $macGiver = Registry;:buildMac(
        MacEnum::MAC_HMAC(),
        HashEnum::HASH_MD5(),
        '0123456789abcdef',     // Secret key
        '',                     // Nonce, for algorithms that require one
        true
    );

    // Pass the data to process to the implementation.
    $macGiver->update(file_get_contents("/path/to/some.data"));

    // Retrieve the resulting tag/MAC.
    // The argument given to finish() decides whether the tag
    // should be returned in raw binary form (true) or not (false).
    $tag = $macGiver->finish(true);


.. vim: ts=4 et
