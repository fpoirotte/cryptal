<?php

namespace fpoirotte\Cryptal;

use \fpoirotte\Cryptal\CryptoInterface;

/**
 * A factory to instanciate cryptography implementations.
 */
final class CryptoFactory
{
    /**
     * Retrieve an implementation for the given
     * cipher & mode combination.
     *
     * \param opaque $cipher
     *      One of the \c CIPHER_* constants from
     *      \fpoirotte\Cryptal\CryptoInterface.
     *
     * \param opaque $mode
     *      One of the \c MODE_* constants from
     *      \fpoirotte\Cryptal\CryptoInterface.
     *
     * \retval fpoirotte::Cryptal::CryptoInterface
     *      An implementation for the given
     *      cipher & mode combination.
     */
    public static function getImplementation($cipher, $mode)
    {
        if (!class_exists('\\fpoirotte\\Cryptal\\Implementation', true)) {
            throw new \Exception('No available implementation');
        }

        use \fpoirotte\Cryptal\Implementation;

        if (!(Implementation instanceof CryptoInterface)) {
            throw new \Exception('Invalid implementation');
        }

        $ciphers = Implemenration::getCiphers();
        $modes = Implemenration::getModes();

        if (!isset($ciphers[$cipher], $modes[$mode])) {
            throw new \Exception('Unsupported cipher/mode combination');
        }

        return new Implementation($ciphers[$cipher], $modes[$mode]);
    }
}
