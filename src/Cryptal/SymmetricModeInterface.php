<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\Implementers\CryptoInterface;

/**
 * Encryption/decryption mode where the same primitive
 * is used for both encryption and decryption.
 */
interface SymmetricModeInterface
{
    /**
     * Construct an encryption/decryption mode of operations.
     *
     * \param CryptoInterface $impl
     *      Cryptographic implementation.
     *
     * \param string $iv
     *      Initialization Vector for the cipher.
     *
     * \param int $tagLength
     *      Length (in bytes) of the tags to generate (AEAD only).
     */
    public function __construct(CryptoInterface $impl, $iv, $tagLength);

    /**
     * Encrypt some data.
     *
     * \param string $data
     *      Data to encrypt.
     *
     * \param resource $context
     *      Stream context for the operation.
     */
    public function encrypt($data, $context);
}
