<?php

namespace fpoirotte\Cryptal\Tests;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\RegistryWrapper;

class DummyPlugin implements PluginInterface
{
    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        // Do nothing
    }
}
