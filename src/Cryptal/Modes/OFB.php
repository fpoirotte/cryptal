<?php

namespace fpoirotte\Cryptal\Modes;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\SymmetricModeInterface;

/**
 * Output Feedback mode
 */
class OFB implements SymmetricModeInterface
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
        $res = $this->cipher->encrypt('', $this->iv);
        $this->iv = $res;
        return $res ^ $data;
    }
}
