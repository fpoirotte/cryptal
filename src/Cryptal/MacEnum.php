<?php

namespace fpoirotte\Cryptal;

use fpoirotte\EnumTrait;

/**
 * Supported algorithms for Message Authentication Codes.
 */
final class MacEnum implements \Serializable
{
    use EnumTrait;

    /// Block-cipher-based MAC (also known as One-Key MAC v1 [OMAC1])
    private $MAC_CMAC;

    /// Keyed-hash MAC
    private $MAC_HMAC;

    /// Parallelizable MAC
    private $MAC_PMAC;

    /// Poly1305 Message Authenticator.
    private $MAC_POLY1305;

    /// Universal hashing-based MAC with 32-bit output
    private $MAC_UMAC_32;

    /// Universal hashing-based MAC with 64-bit output
    private $MAC_UMAC_64;

    /// Universal hashing-based MAC with 96-bit output
    private $MAC_UMAC_96;

    /// Universal hashing-based MAC with 128-bit output
    private $MAC_UMAC_128;
}
