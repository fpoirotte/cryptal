<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\RegistryWrapper;

/**
 * Interface for a Cryptal plugin.
 */
interface PluginInterface
{
    /**
     * Register the various algorithms supported by the plugin.
     *
     * \param RegistryWrapper $registry
     *      Registry whose methods should be called to register
     *      the various algorithms supported by the plugin.
     */
    public static function registerAlgorithms(RegistryWrapper $registry);
}
