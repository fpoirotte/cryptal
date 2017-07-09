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
     *      An exception is thrown when an error occurs.
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

        $streams = array(
            'cryptal.encrypt'   => "\\fpoirotte\Cryptal\\Streams\\Crypto",
            'cryptal.decrypt'   => "\\fpoirotte\Cryptal\\Streams\\Crypto",
            'cryptal.hash'      => "\\fpoirotte\Cryptal\\Streams\\Hash",
            'cryptal.mac'       => "\\fpoirotte\Cryptal\\Streams\\Mac",
        );

        foreach ($streams as $stream => $cls) {
            if (!stream_wrapper_register($stream, $cls)) {
                throw new \Exception("Failed to register '$stream' stream wrapper");
            }
        }

        $inited = true;
        return true;
    }
}
