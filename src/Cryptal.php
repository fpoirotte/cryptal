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

        $filters = array(
            'cryptal.binify'    => "\\fpoirotte\Cryptal\\Filters\\Binify",
            'cryptal.hexify'    => "\\fpoirotte\Cryptal\\Filters\\Hexify",
            'cryptal.encrypt'   => "\\fpoirotte\Cryptal\\Filters\\Crypto",
            'cryptal.decrypt'   => "\\fpoirotte\Cryptal\\Filters\\Crypto",
            'cryptal.hash'      => "\\fpoirotte\Cryptal\\Filters\\Hash",
            'cryptal.mac'       => "\\fpoirotte\Cryptal\\Filters\\Mac",
        );

        foreach ($filters as $filter => $cls) {
            if (!stream_filter_register($filter, $cls)) {
                throw new \Exception("Failed to register '$filter' stream filter");
            }
        }

        $inited = true;
        return true;
    }
}
