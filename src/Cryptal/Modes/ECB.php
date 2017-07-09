<?php

namespace fpoirotte\Cryptal\Modes;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\AsymmetricModeInterface;

/**
 * Electronic Codebook mode
 */
class ECB implements AsymmetricModeInterface
{
    /// Implementation
    protected $cipher;

    public function __construct(CryptoInterface $cipher, $iv, $tagLength)
    {
        $this->cipher = $cipher;
    }

    public function encrypt($data, $context)
    {
        return $this->cipher->encrypt('', $data);
    }

    public function decrypt($data, $context)
    {
        return $this->cipher->decrypt('', $data);
    }
}
