<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\SubAlgorithmInterface;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;

/**
 * Interface for encryption/decryption primitives.
 */
interface CryptoInterface extends SubAlgorithmInterface
{
    const DEFAULT_TAG_LENGTH = 16;

    /**
     * Construct a new encryption/decryption context.
     *
     * \param CipherEnum $cipher
     *      Cipher algorithm to use.
     *
     * \param ModeEnum $mode
     *      Cryptography mode to apply to the cipher.
     *
     * \param PaddingInterface $padding
     *      Padding scheme to use.
     *
     * \param string $key
     *      Secret key used for encryption/decryption.
     *
     * \param int $tagLength
     *      Length (in bytes) of the authentication tags to generate.
     *
     * \note
     *      The \a $tagLength parameter is unused unless
     *      the supplied mode supports Authenticated Encryption
     *      with Additional Data (AEAD).
     */
    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    );

    /**
     * Encrypt some data.
     *
     * \param string $iv
     *      Initialization Vector for the operation.
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
    public function encrypt($iv, $data, &$tag = null, $aad = '');

    /**
     * Decrypt some data.
     *
     * \param string $iv
     *      Initialization Vector for the operation.
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
    public function decrypt($iv, $data, $tag = null, $aad = '');

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
