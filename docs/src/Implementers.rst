Implementers
============

This page contains guidelines for implementers.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**
in this document are to be interpreted as described in :rfc:`2119`.

Guidelines
----------

New implementations **MUST** be delivered as Composer packages.

Each such package **MUST**:

*   Provide a concrete implementation for the ``\fpoirotte\Cryptal\CryptoInterface``
    interface and name that class ``\fpoirotte\Cryptal\Implementation``.

*   Add ``fpoirotte/cryptal`` to the ``requires`` section
    in their :file:`composer.json` file.

*   Add ``fpoirotte/cryptal-implementation`` to the ``provides`` section
    in their :file:`composer.json` file.


Existing implementations
------------------------

A list of existing implementations is available on
`Packagist <https://packagist.org/providers/fpoirotte/cryptal-implementation>`_.

.. vim: ts=4 et

