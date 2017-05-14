<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\SymmetricModeInterface;

/**
 * Encryption/decryption mode where the primitives
 * for encryption and decryption are different.
 */
interface AsymmetricModeInterface extends SymmetricModeInterface
{
    /**
     * Decrypt some data.
     *
     * \param string $data
     *      Data to decrypt.
     *
     * \param resource $context
     *      Stream context for the operation.
     */
    public function decrypt($data, $context);
}
