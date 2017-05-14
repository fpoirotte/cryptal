<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\PaddingInterface;

/**
 * Interface for a cryptographic implementation.
 */
interface CryptoInterface
{
    /**
     * Supported ciphers.
     *
     * \note
     *      The identifier associated with each cipher
     *      may change at any point without prior notice
     *      as new ciphers are added and older ones removed.
     *      Users are therefore advised to use the constants
     *      rather than hard-coded values in their code.
     */

    /// Triple-DES cipher
    const CIPHER_3DES = 1;

    /// Advanced Encryption Standard cipher with a 128 bit key
    const CIPHER_AES_128 = 2;

    /// Advanced Encryption Standard cipher with a 192 bit key
    const CIPHER_AES_192 = 3;

    /// Advanced Encryption Standard cipher with a 256 bit key
    const CIPHER_AES_256 = 4;

    /// Blowfish cipher
    const CIPHER_BLOWFISH = 7;

    /// Camelia cipher with a 128 bit key
    const CIPHER_CAMELIA_128 = 8;

    /// Camelia cipher with a 192 bit key
    const CIPHER_CAMELIA_192 = 9;

    /// Camelia cipher with a 256 bit key
    const CIPHER_CAMELIA_256 = 10;

    /// CAST5 cipher (also known as CAST-128 due to its use of a 128 bit key)
    const CIPHER_CAST5 = 11;

    /// Data Encryption Standard cipher
    const CIPHER_DES = 12;

    /// RC2 cipher
    const CIPHER_RC2 = 13;

    /// RC4 cipher
    const CIPHER_RC4 = 14;

    /// SEED cipher
    const CIPHER_SEED = 15;

    /// Twofish cipher
    const CIPHER_TWOFISH = 16;

    /**
     * Supported encrypted/decryption modes.
     *
     * \note
     *      The identifier associated with each mode
     *      may change at any point without prior notice
     *      as new modes are added and older ones removed.
     *      Users are therefore advised to use the constants
     *      rather than hard-coded values in their code.
     */

    /// Cipher Block Chaining mode
    const MODE_CBC = 1;

    /// Counter with CBC-MAC mode
    const MODE_CCM = 2;

    /// Cipher Feedback mode
    const MODE_CFB = 3;

    /// Counter mode
    const MODE_CTR = 4;

    /// EAX mode
    const MODE_EAX = 5;

    /// Electronic Codebook mode
    const MODE_ECB = 6;

    /// Galois-Counter Mode
    const MODE_GCM = 7;

    /// Offset Codebook mode
    const MODE_OCB = 8;

    /// Output Feedback mode
    const MODE_OFB = 9;

    /// XEX-based tweaked-codebook mode with ciphertext stealing
    const MODE_XTS = 10;

    /**
     * Construct a new encryption/decryption context.
     *
     * \param opaque $cipher
     *      One of the \c CIPHER_* constants from CryptoInterface.
     *
     * \param opaque $mode
     *      One of the \c MODE_* constants from CryptoInterface.
     *
     * \param PaddingInterface $padding
     *      Padding scheme to use.
     *
     * \param string $tagLength
     *      Length (in bytes) of the authentication tags to generate.
     *
     * \note
     *      The \a $tagLength parameter is unused unless
     *      the required mode supports Authenticated Encryption
     *      with Additional Data (AEAD).
     *      \c MODE_GCM & \c MODE_EAX are known to support AEAD.
     */
    public function __construct($cipher, $mode, PaddingInterface $padding, $tagLength = 16);

    /**
     * Encrypt some data.
     *
     * \param string $iv
     *      Initialization Vector for the operation.
     *
     * \param string $key
     *      Secret key used during the operation.
     *
     * \param string $data
     *      Data to encrypt.
     *
     * \param string $tag
     *      Variable where the generated tag will be stored.
     *
     * \param string $aad
     *      Additional authenticated data.
     *
     * \retval string
     *      Ciphertext (encrypted data).
     *
     * \note
     *      The \a $iv parameter is unused for some modes
     *      of operations (namely \c MODE_ECB).
     *      Still, this parameter is mandatory and an empty
     *      string may be passed for those modes.
     *
     * \note
     *      An exception is thrown in case encryption fails.
     *
     * \note
     *      The \a $aad & \a $tag parameters are unused unless
     *      the required mode supports Authenticated Encryption
     *      with Additional Data (AEAD).
     *      \c MODE_GCM & \c MODE_EAX are known to support AEAD.
     */
    public function encrypt($iv, $key, $data, &$tag = null, $aad = '');

    /**
     * Decrypt some data.
     *
     * \param string $iv
     *      Initialization Vector for the operation.
     *
     * \param string $key
     *      Secret key used during the operation.
     *
     * \param string $data
     *      Data to decrypt.
     *
     * \param string $tag
     *      Authentication tag.
     *
     * \param string $aad
     *      Additional authenticated data.
     *
     * \retval string
     *      Plaintext (decrypted data).
     *
     * \note
     *      The \a $iv parameter is unused for some modes
     *      of operations (namely \c MODE_ECB).
     *      Still, this parameter is mandatory and an empty
     *      string may be passed for those modes.
     *
     * \note
     *      An exception is thrown in case decryption fails,
     *      or the given authentication tag is incorrect (AEAD-only).
     *
     * \note
     *      The \a $aad & \a $tag parameters are unused unless
     *      the required mode supports Authenticated Encryption
     *      with Additional Data (AEAD).
     *      \c MODE_GCM & \c MODE_EAX are known to support AEAD.
     */
    public function decrypt($iv, $key, $data, $tag = null, $aad = '');

    /**
     * Get the size of the Initialization Vector, in bytes.
     *
     * \retval int
     *      Required size for the Initialization Vector.
     *      Might be zero in case the given cipher/mode combination
     *      does not require an initialization vector.
     */
    public function getIVSize();

    /**
     * Get the block size, in bytes.
     *
     * \retval int
     *      Required size for each block.
     *      Might be zero in case the given cipher/mode combination
     *      does not use blocks.
     */
    public function getBlockSize();
}
