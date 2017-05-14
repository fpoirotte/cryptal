<?php

namespace fpoirotte;

use fpoirotte\Cryptal\CryptoInterface;

/**
 * Cryptography Abstraction Layer.
 */
class Cryptal
{
    /**
     * Initialize the abstraction layer.
     *
     * \retval bool
     *      Returns \b true on the first successful invocation
     *      and \b false on successive ones.
     *
     * \throw Exception
     *      An exception is thrown when no valid implementation
     *      can be found.
     *
     * \note
     *      This method can safely be called multiple times.
     */
    public static function init()
    {
        static $inited = false;

        if ($inited) {
            return false;
        }

        if (!class_exists("\\fpoirotte\\Cryptal\\Implementation", true) ||
            !(\fpoirotte\Cryptal\Implementation instanceof CryptoInterface)) {
            throw new \Exception('No valid implementation found');
        }

        stream_wrapper_register("cryptal.encrypt", "\\fpoirotte\Cryptal\\CryptoStream")
            or die("Failed to register 'cryptal.encrypt' stream wrapper");
        stream_wrapper_register("cryptal.decrypt", "\\fpoirotte\Cryptal\\CryptoStream")
            or die("Failed to register 'cryptal.decrypt' stream wrapper");

        $inited = true;
        return true;
    }
}
