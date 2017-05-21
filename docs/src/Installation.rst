Installation
============

Cryptal relies on `Composer <https://getcomposer.org/>`_ for its installation.
The project is also made so that various features are provided by separate
abstractions.

To use Cryptal in your project, just add requirements on the feature(s)
you would like to use:

..  sourcecode:: bash

    $ # Abstraction layer for encryption/decryption
    $ php composer.php require fpoirotte/cryptal-crypto-impl
    $
    $ # Abstraction layer for hashes
    $ php composer.php require fpoirotte/cryptal-hash-impl
    $
    $ # Abstraction layer for Message Authentication Codes
    $ php composer.php require fpoirotte/cryptal-mac-impl

Composer will then automatically install an implementation for the selected
abstraction layer(s) that is compatible with your PHP installation.

.. vim: ts=4 et

