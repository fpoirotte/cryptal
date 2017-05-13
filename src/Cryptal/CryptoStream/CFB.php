<?php

namespace fpoirotte\Cryptal\CryptoStream;

use fpoirotte\Cryptal\CryptoInterface;

class CFB
{
    protected $impl;
    protected $key;
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
        $res = $this->impl->encrypt('', $this->key, $this->iv) ^ $data;
        $this->iv = $res;
        return $res;
    }

    public function decrypt($data, $context)
    {
        $res = $this->impl->encrypt('', $this->key, $this->iv) ^ $data;
        $this->iv = $data;
        return $res;
    }
}
