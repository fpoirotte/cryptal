<?php

namespace fpoirotte\Cryptal\Modes;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\AsymmetricModeInterface;

/**
 * Cipher Block Chaining mode
 */
class CBC implements AsymmetricModeInterface
{
    /// Implementation
    protected $impl;

    /// Secret key
    protected $key;

    /// Initialization Vector
    protected $iv;

    public function __construct(CryptoInterface $impl, $key, $iv, $tagLength)
    {
        $ivSize     = strlen($iv);
        $blockSize  = $impl->getBlockSize();
        if ($ivSize !== $blockSize) {
            throw new \Exception("Invalid IV size (got $ivSize bytes; should be $blockSize)");
        }

        $this->impl = $impl;
        $this->key  = $key;
        $this->iv   = $iv;
    }

    public function encrypt($data, $context)
    {
        $data ^= $this->iv;
        $res = $this->impl->encrypt('', $this->key, $data);
        $this->iv = $res;
        return $res;
    }

    public function decrypt($data, $context)
    {
        $res = $this->impl->decrypt('', $this->key, $data) ^ $this->iv;
        $this->iv = $data;
        return $res;
    }
}
