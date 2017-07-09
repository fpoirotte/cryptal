<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;

/**
 * Supported cipher algorithms.
 */
final class CipherEnum extends SubAlgorithmAbstractEnum
{
    /// Triple-DES cipher
    private $CIPHER_3DES;

    /// Advanced Encryption Standard cipher with a 128 bit key
    private $CIPHER_AES_128;

    /// Advanced Encryption Standard cipher with a 192 bit key
    private $CIPHER_AES_192;

    /// Advanced Encryption Standard cipher with a 256 bit key
    private $CIPHER_AES_256;

    /// Blowfish cipher
    private $CIPHER_BLOWFISH;

    /// Camelia cipher with a 128 bit key
    private $CIPHER_CAMELIA_128;

    /// Camelia cipher with a 192 bit key
    private $CIPHER_CAMELIA_192;

    /// Camelia cipher with a 256 bit key
    private $CIPHER_CAMELIA_256;

    /// CAST5 cipher (also known as CAST-128 due to its use of a 128 bit key)
    private $CIPHER_CAST5;

    /// ChaCha20 cipher, with optional authenticated data
    private $CIPHER_CHACHA20;

    /// ChaCha20 cipher with authenticated data (OpenSSH variant)
    private $CIPHER_CHACHA20_OPENSSH;

    /// Data Encryption Standard cipher
    private $CIPHER_DES;

    /// RC2 cipher
    private $CIPHER_RC2;

    /// RC4 cipher
    private $CIPHER_RC4;

    /// SEED cipher
    private $CIPHER_SEED;

    /// Twofish cipher
    private $CIPHER_TWOFISH;
}
