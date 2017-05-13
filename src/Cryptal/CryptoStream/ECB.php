<?php

namespace fpoirotte\Cryptal\CryptoStream;

use fpoirotte\Cryptal\CryptoInterface;

class ECB
{
    protected $impl;
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
