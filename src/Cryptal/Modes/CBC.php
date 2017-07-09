<?php

namespace fpoirotte\Cryptal\Modes;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\AsymmetricModeInterface;

/**
 * Cipher Block Chaining mode
 */
class CBC implements AsymmetricModeInterface
{
    /// Cipher
    protected $cipher;

    /// Initialization Vector
    protected $iv;

    public function __construct(CryptoInterface $cipher, $iv, $tagLength)
    {
        $ivSize     = strlen($iv);
        $blockSize  = $cipher->getBlockSize();
        if ($ivSize !== $blockSize) {
            throw new \Exception("Invalid IV size (got $ivSize bytes; should be $blockSize)");
        }

        $this->cipher   = $cipher;
        $this->iv       = $iv;
    }

    public function encrypt($data, $context)
    {
        $data ^= $this->iv;
        $res = $this->cipher->encrypt('', $data);
        $this->iv = $res;
        return $res;
    }

    public function decrypt($data, $context)
    {
        $res = $this->cipher->decrypt('', $data) ^ $this->iv;
        $this->iv = $data;
        return $res;
    }
}
