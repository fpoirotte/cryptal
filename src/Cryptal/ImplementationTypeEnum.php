<?php

namespace fpoirotte\Cryptal;

use fpoirotte\EnumTrait;

final class ImplementationTypeEnum implements \Serializable
{
    use EnumTrait;

    /// The implementation uses assembly/highly-optimized code.
    private $TYPE_ASSEMBLY;

    /// The implementation uses compiled code (eg. C/C++).
    private $TYPE_COMPILED;

    /// The implementation is based on userland PHP code.
    private $TYPE_USERLAND;
}
