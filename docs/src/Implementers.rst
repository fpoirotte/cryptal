Implementers
============

This page contains guidelines for implementers.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**
in this document are to be interpreted as described in :rfc:`2119`.

Guidelines
----------

New implementations **MUST** be delivered as Composer packages.
Such a package **MUST** provide an implementation for one or several
of the interfaces defined in the ``\fpoirotte\Cryptal\Implementers`` namespace.

It is **RECOMMENDED** that implementers always support as many algorithms
recognized by the Cryptography Abstraction Layer as the underlying library
and Cryptal permit when adding support for a feature.

The following sections describes how to turn a regular Composer package
into a Cryptal plugin.

Creating a new plugin
---------------------

Update your :file:`composer.json` file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The basic skeleton for a plugin's :file:`composer.json` looks like this:

..  sourcecode:: json

    {
        "name": "fpoirotte/cryptal-tomcrypt",
        "type": "cryptal-plugin",
        "description": "Plugin for Cryptal based on LibTomcrypt",
        "license": "MIT",
        "require": {
            "php": ">=5.4",
            "fpoirotte/cryptal": "*"
        },
        "provide": {
            "fpoirotte/cryptal-implementation": "*"
        },
        "autoload": {
            "psr-4": {
                "fpoirotte\\Cryptal\\Plugins\\Tomcrypt": "src/"
            }
        },
        "extra": {
            "cryptal.entrypoint": "fpoirotte\\Cryptal\\Plugins\\Tomcrypt\\Entrypoint"
        }
    }


There are four important things to note:

*   The package's type **MUST** be set to ``cryptal-plugin`` in order for the
    plugin to be properly recognized as such.

*   The package **MUST** contain a requirement on ``fpoirotte/cryptal``
    as part of the ``require`` section, so that the core files needed
    to load and use the plugin are available at runtime.

*   To make it easier to find compatible plugins for Cryptal
    on `Packagist <https://packagist.org/>`_, an implementation
    **SHOULD** ``provide`` the ``fpoirotte/cryptal-implementation``
    virtual package in its :file:`composer.json` file.

    The version number associated with the provided virtual package **SHOULD**
    be set to a sensible value.

*   The package **MUST** declare a key named ``cryptal.entrypoint``
    in the ``extra`` section of their :file:`composer.json` file,
    pointing to a class that implements the
    ``fpoirotte\Cryptal\Implementers\PluginInterface`` interface.

    If your plugin provides implementations for several features
    and you would like each feature to use its own entry point,
    you may also use an array of entry points here in place
    of a string.

Write the code for the entry point
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The entry point is responsible for registering any algorithm implemented
by the plugin into Cryptal's registry.

Assuming the plugin adds support for the AES cipher using 128 bit keys (AES-128)
in Electronic Codebook (ECB) mode, the MD5 hash algorithm and the HMAC message
authentication code, an entry point may look like this:

..  sourcecode:: inline-php

    namespace fpoirotte\Cryptal\Plugins\Tomcrypt;

    use fpoirotte\Cryptal\Implementers\PluginInterface;
    use fpoirotte\Cryptal\ImplementationTypeEnum;
    use fpoirotte\Cryptal\CipherEnum;
    use fpoirotte\Cryptal\ModeEnum;
    use fpoirotte\Cryptal\HashEnum;
    use fpoirotte\Cryptal\MacEnum;

    class Entrypoint implements PluginInterface
    {
        public function registerAlgorithms(RegistryWrapper $registry)
        {
            // Declare support for AES-128 in ECB mode
            $registry->addCipher(
                '\\fpoirotte\\cryptal\\Plugins\\Tomcrypt\\Aes',
                CipherEnum::CIPHER_AES_128(),
                ModeEnum::MODE_ECB(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );

            // Declare support for the MD5 message digest algorithm
            $registry->addHash(
                '\\fpoirotte\\cryptal\\Plugins\\Tomcrypt\\Md5',
                HashEnum::HASH_MD5(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );

            // Declare support for the HMAC message authenticator algorithm
            $registry->addMac(
                '\\fpoirotte\\cryptal\\Plugins\\Tomcrypt\\Hmac',
                MacEnum::MAC_HMAC(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
    }

The ``RegistryWrapper`` provides 3 methods, meant to declare support for
new ciphers (addCipher), hash algorithms (addHash) and message authentication
codes (addMac).

Each of these methods expects the full path to a class providing the algorithm
as their first argument, followed by Cryptal's identifier for that algorithm
and an identifier for the implementation type.

For ciphers, the algorithm identifier is made of two arguments:

*   The cipher's identifier itself
    (one of the values declared in the ``CipherEnum`` enumeration)

*   The mode of operations which can be applied to this cipher
    (one of the values declared in the ``ModeEnum`` enumeration)

For hash and MAC algorithms, just pass the algorithm's identifier defined
in ``HashEnum`` or ``MacEnum``, respectively.

The implementation type **SHOULD** match the actual nature of the algorithm's
implementation:

*   ``TYPE_ASSEMBLY()`` **SHOULD** be used when the underlying code is known
    to be optimized for speed/uses assembly code.

*   ``TYPE_COMPILED()`` **SHOULD** be used for other forms of compiled code,
    such as code from a PHP extension coded in C or C++.

*   ``TYPE_USERLAND()`` **SHOULD** be used for algorithms implemented using
    regular (userland) PHP code, as opposed to code from a PHP extension.

Cryptal uses this information at runtime to determine the fastest/most secure
implementation it can use.

Available plugins
-----------------

You can browse the list of existing plugins for Cryptal on
`Packagist <https://packagist.org/providers/fpoirotte/cryptal-implementation>`_

.. vim: ts=4 et

