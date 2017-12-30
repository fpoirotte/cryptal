Usage
#####

Cryptal provides support for the following main features:

*   Encryption/decryption
*   Hashes (also known as message digests)
*   Message Authentication Codes

For each feature, two sets of interfaces are provided:

*   PHP stream filters, which hide the complexity of the operations
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

Using stream filters
--------------------

..  warning::

    When using the stream filters, the library relies mostly on PHP code
    to handle encryption/decryption. The underlying library is only used
    to provide the cryptographic primitives for the selected cipher
    in `ECB <https://en.wikipedia.org/wiki/Electronic_codebook>`_ mode.

    This hurts performance a bit, but more importantly, this may diminish
    your application's security, because some values (keys, IVs, etc.)
    cannot be safely erased from memory and may linger there even after
    you are done processing the data.

    If you are concerned about these issues, do not use the stream filters.


Encryption
~~~~~~~~~~

Encrypting data is easy:

..  sourcecode:: inline-php

    // Initialize the library
    \fpoirotte\Cryptal::init();

    // Open a new stream
    $stream = stream_socket_client('tcp://localhost:12345');

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

    // Add an encryption layer to the stream.
    $filter = stream_filter_append(
        $stream,
        'cryptal.encrypt',
        // We want the data to be encrypted as we write it.
        STREAM_FILTER_WRITE,
        array(
            // Encrypt the data using AES-128 in CTR mode.
            'algorithm' => CipherEnum::CIPHER_AES_128(),
            'mode'      => ModeEnum::MODE_CTR(),

            // Secret key.
            // Size must be compatible with the cipher's expectations.
            'key'       => '0123456789abcdef',

            // Initialization Vector.
            // Size must be compatible with the cipher's expectations.
            'iv'        => 'abcdef0123456789',
        )
    );

    // We make sure the filter was successfully applied.
    if (false === $filter) {
        throw new \Exception('Could not add the encryption layer');
    }

    // Now that the encryption layer is in place, we can write
    // to the stream just like we would normally do.
    // Any data written to the stream will be encrypted on the fly.
    fwrite($stream, "Some secret message we want to transmit securely");

..  warning::

    When adding the filter, the 3rd argument to ``stream_filter_append()``
    (``$read_write``) should be set to either ``STREAM_FILTER_WRITE``
    if the encryption should happen during writes (eg. via ``fwrite()``),
    or ``STREAM_FILTER_READ`` if it should happen during reads (eg. via
    ``fread()`` or ``fgets()``).

    Using the default value (``STREAM_FILTER_ALL``) means the same filter
    is applied to both operations, which is not supported and may produce
    unexpected results.

Here's another example, this time using Authenticated Encryption with
Associated Data (AEAD):

..  sourcecode:: inline-php

    @TODO


Decryption
~~~~~~~~~~

Decryption works the same way. Just substitute ``cryptal.decrypt`` in place
of ``cryptal.encrypt`` when adding the filter.

When using Authenticated Encryption, @TODO


Filter parameters for ``cryptal.encrypt``/``cryptal.decrypt``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using streams, the following options may be used when adding the filter
to control the way encryption/decryption is performed:

..  list-table:: Parameters for cryptal.encrypt/cryptal.decrypt
    :widths: 10 5 35 50
    :header-rows: 1

    *   - Name
        - Optional
        - Expected type
        - Description

    *   - ``mode``
        - yes
        - ``\fpoirotte\Cryptal\ModeEnum``
        - The cipher's mode of operations to use.

          This parameter is important as the various modes offer different
          security garantees. Make sure you have read documentation on the
          various modes and their implications before setting this value.

    *   - ``algorithm``
        - yes
        - ``\fpoirotte\Cryptal\CipherEnum``
        - The cipher algorithm to use to encrypt/decrypt the data.

          This parameter is important as the various ciphers offer different
          security garantees. Make sure you have read documentation on the
          various ciphers and their limitations before setting this value.

    *   - ``allowUnsafe``
        - no
        - boolean
        - Whether userland PHP implementations may be used or not.
          Defaults to ``false``.

          While those implementations add support for some rarely used
          algorithms, they are usually way slower than implementations
          based on PHP extensions.

          Also, those implementations are considered unsafe because they cannot
          protect the application from certain classes of attacks like
          PHP extensions usually do (eg. side-channel attacks).

          Last but not least, when using those implementations, secret values
          may reside in memory for longer than is actually necessary
          (possibly even longer than the program's actual execution time),
          making them vulnerable to memory forensic techniques and such.

    *   - ``data``
        - no
        - string
        - Additional Data to authenticate when using `Authenticated Encryption
          <https://en.wikipedia.org/wiki/Authenticated_encryption>`_

    *   - ``iv``
        - yes/no
        - string
        - Initialization Vector for the cipher.
          Whether this parameter is optional or not depends of the
          encryption/decryption mode used.

    *   - ``key``
        - yes
        - string
        - Symmetric key to use for encryption/decryption

    *   - ``padding``
        - no
        - ``\fpoirotte\Cryptal\PaddingInterface``
        - Padding scheme to use. Defaults to no padding.

    *   - ``tag``
        - no
        - string
        - Authentication tag for the current block. This value is set by the
          filter during encryption of a block. It should be set manually
          when decrypting, before passing a block to decrypt to the stream.

    *   - ``tagLength``
        - no
        - integer
        - Desired tag length (in bytes) when using `Authenticated Encryption
          <https://en.wikipedia.org/wiki/Authenticated_encryption>`_.

          Defaults to 16 bytes (128 bits).
          
          This parameters is only used during encryption, as it can be deduced
          from the ``tag``'s actual length when decrypting.


Padding
~~~~~~~

By default, no padding is applied to streams (ie. the padding scheme
is set to an instance of ``fpoirotte\Cryptal\Padding\None``).

If you need to use another padding scheme, you can easily swap the default
for an alternate implementation. Just set the ``padding`` filter parameter
to an instance of the padding scheme to use when adding the filter:

..  sourcecode:: inline-php

    use fpoirotte\Cryptal\Padding\AnsiX923;

    // Open the stream
    $stream = fopen(..., 'wb');

    stream_filter_append(
        $stream,
        'cryptal.encrypt',
        STREAM_FILTER_WRITE,
        array(
                'key'       => '0123456789abcdef',
                'IV'        => 'abcdef0123456789',
                'algorithm' => CipherEnum::CIPHER_AES_128(),
                'mode'      => ModeEnum::MODE_CTR(),

                // Use the ANSI X.923 padding scheme.
                'padding'   => new AnsiX923,
        )
    );

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

Using stream filters
--------------------

Replicating ``md5_file()`` using Cryptal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Hashing data using streams is really easy. For example, to obtain an MD5
message digest for a file (similar to what the PHP ``md5_file()`` function
returns), the following snippet can be used:

..  sourcecode:: inline-php

    // Initialize the library
    \fpoirotte\Cryptal::init();

    // Open the binary file for reading.
    $fp = fopen("/path/to/some.data", "rb");

    // Add the hashing filter to the stream.
    stream_filter_append(
        $fp,
        'cryptal.hash',
        // We want to compute the hash based on data read from the file.
        STREAM_FILTER_READ,
        array(
            'algorithm' => HashEnum::HASH_MD5()
        )
    );

    // Read the resulting message digest (returned in raw form).
    // The MD5 algorithm produces a 128-bit hash (16 bytes).
    $hash = stream_get_contents($fp);

..  warning::

    When adding the filter, the 3rd argument to ``stream_filter_append()``
    (``$read_write``) should be set to either ``STREAM_FILTER_WRITE``
    if the hashing should happen during writes (eg. via ``fwrite()``),
    or ``STREAM_FILTER_READ`` if it should happen during reads (eg. via
    ``fread()`` or ``fgets()``).

    Using the default value (``STREAM_FILTER_ALL``) means the same filter
    is applied to both operations, which is not supported and may produce
    unexpected results.


Filter parameters for ``cryptal.hash``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using streams, the following options may be used when adding the filter
to control the way the message digest is computed:

..  list-table:: Parameters for cryptal.hash
    :widths: 10 5 35 50
    :header-rows: 1

    *   - Name
        - Optional
        - Expected type
        - Description

    *   - ``algorithm``
        - yes
        - ``\fpoirotte\Cryptal\HashEnum``
        - The algorithm to use to hash the data.

          This parameter is important as the various algorithms offer different
          security garantees. Make sure you have read documentation on the
          various algorithms and their limitations before setting this value.

    *   - ``allowUnsafe``
        - no
        - boolean
        - Whether userland PHP implementations may be used or not.
          Defaults to ``false``.

          While those implementations add support for some rarely used
          algorithms, they are usually way slower than implementations
          based on PHP extensions.

          Also, those implementations are considered unsafe because they cannot
          protect the application from certain classes of attacks like
          PHP extensions usually do (eg. side-channel attacks).

          Last but not least, when using those implementations, secret values
          may reside in memory for longer than is actually necessary
          (possibly even longer than the program's actual execution time),
          making them vulnerable to memory forensic techniques and such.


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

Before computing any MAC, we suggest that you first read some documentation
about whatever algorithm you plan on using and then learn about its specific
requirements and limitations.

Using stream filters
--------------------

Quick example: HMAC-MD5 on a file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To compute a MAC using the stream interface, just use code similar to this one:

..  sourcecode:: inline-php

    // Initialize the library
    \fpoirotte\Cryptal::init();

    // Open the binary file for reading.
    $macGiver = fopen("/path/to/some.data", "rb");

    // Add the MAC filter to the stream.
    stream_filter_append(
        $macGiver,
        'cryptal.mac',
        // We want to compute the MAC based on data read from the file.
        STREAM_FILTER_READ,
        array(
            'algorithm'         => MacEnum::MAC_HMAC(),
            'innerAlgorithm'    => HashEnum::HASH_MD5(),

            // Size must be compatible with the algorithms in use.
            'key'               => '0123456789abcdef',
        )
    );

    // Retrieve the Message Authentication Code in raw binary form.
    // The HMAC-MD5 algorithm produces a 128-bit hash (16 bytes).
    $mac = stream_get_contents($macGiver);


..  warning::

    When adding the filter, the 3rd argument to ``stream_filter_append()``
    (``$read_write``) should be set to either ``STREAM_FILTER_WRITE``
    if the tag computation should happen during writes (eg. via ``fwrite()``),
    or ``STREAM_FILTER_READ`` if it should happen during reads (eg. via
    ``fread()`` or ``fgets()``).

    Using the default value (``STREAM_FILTER_ALL``) means the same filter
    is applied to both operations, which is not supported and may produce
    unexpected results.


Filter parameters for ``cryptal.mac``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using streams, the following options may be used when adding the filter
to control the way the message authentication code is computed:

..  list-table:: Parameters for cryptal.mac
    :widths: 10 5 35 50
    :header-rows: 1

    *   - Name
        - Optional
        - Expected type
        - Description

    *   - ``algorithm``
        - yes
        - ``\fpoirotte\Cryptal\MacEnum``
        - Outer algorithm to use to perform the computation.

          This parameter is important as the various algorithms offer different
          security garantees. Make sure you have read documentation on the
          various algorithms and their limitations before setting this value.

    *   - ``innerAlgorithm``
        - yes
        - ``\fpoirotte\Cryptal\SubAlgorithmAbstractEnum``
        - Inner algorithm to use to perform the computation.

          Depending on the selected ``algorithm``, this parameter should be set
          to either an instance of ``\fpoirotte\Cryptal\CipherEnum`` or
          ``\fpoirotte\Cryptal\HashEnum``.

          This parameter is important as the various algorithms offer different
          security garantees. Make sure you have read documentation on the
          various algorithms and their limitations before setting this value.

    *   - ``allowUnsafe``
        - no
        - boolean
        - Whether userland PHP implementations may be used or not.
          Defaults to ``false``.

          While those implementations add support for some rarely used
          algorithms, they are usually way slower than implementations
          based on PHP extensions.

          Also, those implementations are considered unsafe because they cannot
          protect the application from certain classes of attacks like
          PHP extensions usually do (eg. side-channel attacks).

          Last but not least, when using those implementations, secret values
          may reside in memory for longer than is actually necessary
          (possibly even longer than the program's actual execution time),
          making them vulnerable to memory forensic techniques and such.

    *   - ``nonce``
        - yes/no
        - string
        - Nonce to make the output less predictable.
          Whether this parameter is optional or not depends on the
          selected ``algorithm``/``innerAlgorithm``.

    *   - ``key``
        - yes
        - string
        - Symmetric key to use for the computation



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


Miscelleanous features
======================

In addition to the ones listed above, Cryptal also provides the following
filters:

*   ``cryptal.binify`` can be used to convert an hexadecimal-encoded string
    into its binary counterpart on the fly
    (eg. ``4372797074616c`` -> ``Cryptal``).

*   ``cryptal.hexify`` does the reverse operation and can be used to convert
    a string into its hexadecimal representation
    (eg. ``Cryptal`` -> ``4372797074616c``).
    It accepts a single option named ``uppercase``. When set to ``true``,
    the filter will generate its output using uppercase characters instead
    of the (default) lowercase characters.


.. vim: ts=4 et
