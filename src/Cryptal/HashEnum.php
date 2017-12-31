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
    private $HASH_SHA2_224;

    /// Secure Hash Algorithm 2 (256 bit hashes)
    private $HASH_SHA2_256;

    /// Secure Hash Algorithm 2 (384 bit hashes)
    private $HASH_SHA2_384;

    /// Secure Hash Algorithm 2 (512 bit hashes)
    private $HASH_SHA2_512;

    /// Secure Hash Algorithm 3 (224 bit hashes)
    private $HASH_SHA3_224;

    /// Secure Hash Algorithm 3 (256 bit hashes)
    private $HASH_SHA3_256;

    /// Secure Hash Algorithm 3 (384 bit hashes)
    private $HASH_SHA3_384;

    /// Secure Hash Algorithm 3 (512 bit hashes)
    private $HASH_SHA3_512;
}
