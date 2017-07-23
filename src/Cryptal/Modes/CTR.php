<?php

namespace fpoirotte\Cryptal\Modes;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\SymmetricModeInterface;

/**
 * Counter mode
 */
class CTR implements SymmetricModeInterface
{
    /// Cipher
    protected $cipher;

    /// Counter
    protected $counter;

    /// Cipher block size
    protected $blockSize;

    public function __construct(CryptoInterface $cipher, $iv, $tagLength)
    {
        $ivSize     = strlen($iv);
        $blockSize  = $cipher->getBlockSize();
        if ($ivSize !== $blockSize) {
            throw new \Exception("Invalid IV size (got $ivSize bytes; should be $blockSize)");
        }

        $this->cipher       = $cipher;
        $this->counter      = $iv;
        $this->blockSize    = $blockSize;
    }

    /// Increment the value of the counter by one.
    protected function incrementCounter()
    {
        for ($i = $this->blockSize - 1; $i >= 0; $i--) {
            // chr() takes care of overflows automatically.
            $this->counter[$i] = chr(ord($this->counter[$i]) + 1);

            // Stop, unless the incremented generated an overflow.
            // In that case, we continue to propagate the carry.
            if ("\x00" !== $this->counter[$i]) {
                break;
            }
        }
    }

    public function encrypt($data, $context)
    {
        $res = $this->cipher->encrypt('', $this->counter);
        $this->incrementCounter();
        return $res ^ $data;
    }
}
