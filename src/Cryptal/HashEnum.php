<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;

/**
 * Supported hashing/message digest algorithms.
 */
final class HashEnum extends SubAlgorithmAbstractEnum
{
    /// Message Digest 2 (128 bit hashes); for backward compatibility
    private $HASH_MD2;

    /// Message Digest 4 (128 bit hashes); for backward compatibility
    private $HASH_MD4;

    /// Message Digest 5 (128 bit hashes); for backward compatibility
    private $HASH_MD5;

    /// RACE Integrity Primitives Evaluation Message Digest (160 bit hashes)
    private $HASH_RIPEMD160;

    /// Secure Hash Algorithm 1 (160 bit hashes); for backward compatibility
    private $HASH_SHA1;

    /// Secure Hash Algorithm 2 (224 bit hashes)
    private $HASH_SHA224;

    /// Secure Hash Algorithm 2 (256 bit hashes)
    private $HASH_SHA256;

    /// Secure Hash Algorithm 2 (384 bit hashes)
    private $HASH_SHA384;

    /// Secure Hash Algorithm 2 (512 bit hashes)
    private $HASH_SHA512;
}
