<?php

namespace fpoirotte;

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

        $interfaces = class_implements("\\fpoirotte\\Cryptal\\Implementation", true);
        if (!$interfaces || !in_array("fpoirotte\Cryptal\CryptoInterface", $interfaces)) {
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
