Implementers
============

This page contains guidelines for implementers.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**
in this document are to be interpreted as described in :rfc:`2119`.

Guidelines
----------

New implementations **MUST** be delivered as Composer packages.

Such a package :
*   **MUST** contain a requirement on ``fpoirotte/cryptal``
    as part of the ``require`` section in their :file:`composer.json` file.

*   **MUST** provide an implementation for one or several of the interfaces
    defined in the ``\fpoirotte\Cryptal\Implementers`` namespace.

*   **MUST** use ``cryptal-plugin`` as their installer ``type``.

*   **MUST** declare a key named ``cryptal.entrypoint`` in the ``extra`` section
    of their :file:`composer.json` file, pointing to a class implementing
    the ``fpoirotte\Cryptal\Implementers\PluginInterface`` interface.

To make it easier to find compatibles plugins for Cryptal
on `Packagist <https://packagist.org/>`_, an implementation
**MAY** ``provide`` the ``fpoirotte/cryptal-implementation`` virtual package
in their :file:`composer.json`

The version number associated with the provided virtual package **SHOULD**
be set to a sensible value.

It is **RECOMMENDED** that implementers always support as many algorithms
recognized by the Cryptography Abstraction Layer as the underlying library
and Cryptal permit when adding support for a feature.


Creating a new plugin
---------------------

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

Assuming the plugin adds support for the AES cipher using 128 bit keys (AES-128)
in Electronic Codebook (ECB) mode, the MD5 hash algorithm and the HMAC message
authentication code, the entry point will look like this:

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

            // Declare support for MD5
            $registry->addHash(
                '\\fpoirotte\\cryptal\\Plugins\\Tomcrypt\\Md5',
                HashEnum::HASH_MD5(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );

            // Declare support for HMAC
            $registry->addMac(
                '\\fpoirotte\\cryptal\\Plugins\\Tomcrypt\\Hmac',
                MacEnum::MAC_HMAC(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
    }

The implementation type **SHOULD** match the actual nature of the algorithm's
implementation:

*   ``TYPE_ASSEMBLY()`` **SHOULD** be used when the underlying code is known
    to be optimized for speed/uses assembly code.

*   ``TYPE_COMPILED()`` **SHOULD** be used for other forms of compiled code,
    such a code from a PHP extension coded in C or C++.

*   ``TYPE_USERLAND()`` **SHOULD** be used for algorithms implemented using
    regular (userland) PHP code, as opposed to code from a PHP extension.

Existing implementations
------------------------

You can browse the list of existing implementations on
`Packagist <https://packagist.org/providers/fpoirotte/cryptal-implementation>`_

.. vim: ts=4 et

