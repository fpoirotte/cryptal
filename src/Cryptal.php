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

        foreach (array('Crypto', 'Hash', 'Mac') as $lib) {
            $interfaces = @class_implements("\\fpoirotte\\Cryptal\\Implementers\\${lib}");
            $parents    = @class_parents("\\fpoirotte\\Cryptal\\Implementers\\${lib}");
            $bases      = array_merge((array) $interfaces, (array) $parents);

            // If the class does not exist, $bases contains two boolean false values.
            // Otherwise, it should contain the proper interface/abstract base class.
            if (!in_array(false, $bases) && !in_array("fpoirotte\Cryptal\Implementers\\${lib}Interface", $bases)) {
                throw new \Exception("No implementation found for $lib library");
            }
        }

        stream_wrapper_register("cryptal.encrypt", "\\fpoirotte\Cryptal\\Crypto\\Stream")
            or die("Failed to register 'cryptal.encrypt' stream wrapper");
        stream_wrapper_register("cryptal.decrypt", "\\fpoirotte\Cryptal\\Crypto\\Stream")
            or die("Failed to register 'cryptal.decrypt' stream wrapper");

        $inited = true;
        return true;
    }
}
