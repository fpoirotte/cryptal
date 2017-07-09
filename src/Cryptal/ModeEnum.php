<?php

namespace fpoirotte\Cryptal;

use fpoirotte\EnumTrait;

/**
 * Supported cipher operation modes.
 */
final class ModeEnum implements \Serializable
{
    use EnumTrait;

    /// Cipher Block Chaining mode
    private $MODE_CBC;

    /// Counter with CBC-MAC mode
    private $MODE_CCM;

    /// Cipher Feedback mode
    private $MODE_CFB;

    /// Counter mode
    private $MODE_CTR;

    /// EAX mode
    private $MODE_EAX;

    /// Electronic Codebook mode
    private $MODE_ECB;

    /// Galois-Counter Mode
    private $MODE_GCM;

    /// Offset Codebook mode
    private $MODE_OCB;

    /// Output Feedback mode
    private $MODE_OFB;
}
