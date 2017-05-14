<?php

namespace fpoirotte\Cryptal\CryptoStream;

use fpoirotte\Cryptal\CryptoInterface;
use fpoirotte\Cryptal\AsymmetricModeInterface;

/**
 * Electronic Codebook mode
 */
class ECB implements AsymmetricModeInterface
{
    /// Implementation
    protected $impl;

    /// Secret key
    protected $key;

    public function __construct(CryptoInterface $impl, $key, $iv, $tagLength)
    {
        $this->impl = $impl;
        $this->key  = $key;
    }

    public function encrypt($data, $context)
    {
        return $this->impl->encrypt('', $this->key, $data);
    }

    public function decrypt($data, $context)
    {
        return $this->impl->decrypt('', $this->key, $data);
    }
}
