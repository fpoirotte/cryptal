<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\MacEnum;

class RegistryWrapper
{
    private $registry;
    private $packageName;

    public function __construct(Registry $registry, $packageName)
    {
        $this->registry     = $registry;
        $this->packageName  = $packageName;
    }

    public function addCipher($cls, CipherEnum $algo, ModeEnum $mode, ImplementationTypeEnum $type)
    {
        $this->registry->addCipher($this->packageName, $cls, $algo, $mode, $type);
    }

    public function addHash($cls, HashEnum $algo, ImplementationTypeEnum $type)
    {
        $this->registry->addHash($this->packageName, $cls, $algo, $type);
    }

    public function addMac($cls, MacEnum $algo, ImplementationTypeEnum $type)
    {
        $this->registry->addMac($this->packageName, $cls, $algo, $type);
    }
}
