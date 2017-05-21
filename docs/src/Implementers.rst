Implementers
============

This page contains guidelines for implementers.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**
in this document are to be interpreted as described in :rfc:`2119`.

Guidelines
----------

New implementations **MUST** be delivered as Composer packages.

Such a package **MUST** contain a requirement on ``fpoirotte/cryptal``
as part of the ``require`` section in their :file:`composer.json` file.

Such a package **MUST** provide an implementation for one or several
of the interfaces/abstract classes defined in the
``\fpoirotte\Cryptal\Implementers`` namespace.

The implementation's classname **MUST** be the same as the interface
or abstract class name they implement, minus the ``Interface`` suffix.
For example, an implementation of
``\fpoirotte\Cryptal\Implementers\CryptoInterface`` **MUST** be named
``\fpoirotte\Cryptal\Implementers\Crypto``.

An implementation package **MUST** fill in the ``provide`` section of their
:file:`composer.json` file with the appropriate information:

*   If the package contains an implementation for
    ``\fpoirotte\Cryptal\Implementers\CryptoInterface``,
    then ``fpoirotte/cryptal-crypto-impl`` **MUST** be added
    to the list of its provided features.

*   If the package contains an implementation for
    ``\fpoirotte\Cryptal\Implementers\HashInterface``,
    then ``fpoirotte/cryptal-hash-impl`` **MUST** be added
    to the list of its provided features.

*   If the package contains an implementation for
    ``\fpoirotte\Cryptal\Implementers\MacInterface``,
    then ``fpoirotte/cryptal-mac-impl`` **MUST** be added
    to the list of its provided features.

The version number associated with a provided feature **SHOULD** be set
to a sensible value.

A package **MAY** provide implementations for several features defined
in the Cryptography Abstraction Layer.
In that case, an entry **MUST** be added to the package's ``provide`` section
for every implemented feature.

It is **RECOMMENDED** that implementers always support as many algorithms
recognized by the Cryptography Abstraction Layer as the underlying library
permits when adding support for a feature.


Existing implementations
------------------------

You can browse the list of existing implementations on Packagist based
on the features they implement:

*   `Encryption/Decryption <https://packagist.org/providers/fpoirotte/cryptal-crypto-impl>`_
*   `Hashing <https://packagist.org/providers/fpoirotte/cryptal-hash-impl>`_
*   `Message Authentication Codes <https://packagist.org/providers/fpoirotte/cryptal-mac-impl>`_


.. vim: ts=4 et

