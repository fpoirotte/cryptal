<?php

namespace fpoirotte\Cryptal;

/**
 * A cryptographic abstraction
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

    /// CAST5 cipher (also known as CAST-128 due to its use of a 128 bit key)
    const CIPHER_CAST5 = 5;

    /// Data Encryption Standard cipher
    const CIPHER_DES = 6;

    /// Twofish cipher
    const CIPHER_TWOFISH = 8;

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
     * Returns an array mapping supported ciphers (CIPHER_* constants)
     * to the internal code for those ciphers (opaque value).
     *
     * \retval array
     *      Mapping between supported ciphers and their internal code.
     *
     * \note
     *      You can test whether a particular cipher is supported
     *      by this implementation using the following snippet:
     *
     *      $supportedCiphers = $impl->getCiphers();
     *      if (isset($supportedCiphers[CryptoInterface::CIPHER_AES])) {
     *          ...do something...
     *      }
     */
    public static function getCiphers();

    /**
     * Returns an array mapping supported modes (MODE_* constants)
     * to the internal code for those modes (opaque value).
     *
     * \retval array
     *      Mapping between supported modes and their internal code.
     *
     * \note
     *      You can test whether a particular mode is supported
     *      by this implementation using the following snippet:
     *
     *      $supportedModes = $impl->getModes();
     *      if (isset($supportedModes[CryptoInterface::MODE_CBC])) {
     *          ...do something...
     *      }
     */
    public static function getModes();

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
     * \param string $aad
     *      Additional authenticated data.
     *
     * \param string $tagLength
     *      Length (in bytes) of the authentication tag to generate.
     *
     * \param string $tag
     *      Variable where the generated tag will be stored.
     *
     * \retval string
     *      The ciphertext (encrypted data).
     *
     * \note
     *      An exception is thrown in case encryption fails.
     *
     * \note
     *      The \a $aad, \a $tagLength & \a $tag parameters are all unused
     *      unless the required mode supports Authenticated Encryption
     *      with Additional Data (AEAD).
     *      \c MODE_GCM & \c MODE_EAX are known to support AEAD.
     */
    public function encrypt($iv, $key, $data, $aad = '', $tagLength = null, &$tag = null);

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
     * \retval string
     *      The ciphertext (encrypted data).
     *
     * \note
     *      An exception is thrown in case decryption fails,
     *      or the given authentication tag is incorrect (AEAD-only).
     *
     * \note
     *      The \a $tag parameter is unused unless the required mode supports
     *      Authenticated Encryption with Additional Data (AEAD).
     *      \c MODE_GCM & \c MODE_EAX are known to support AEAD.
     */
    public function decrypt($iv, $key, $data, $tag);

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
