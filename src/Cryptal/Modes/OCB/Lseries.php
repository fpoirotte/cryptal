<?php

namespace fpoirotte\Cryptal\Modes\OCB;

use fpoirotte\Cryptal\Implementers\CryptoInterface;

class Lseries implements \ArrayAccess
{
    private $values;

    public function __construct(CryptoInterface $cipher)
    {
        $this->values['*'] = $value = $cipher->encrypt('', str_repeat("\x00", 16));
        $this->values['$'] = $value = self::doubling($value);
        for ($i = 0; $i <= 128; $i++) {
            $this->values[$i] = $value = self::doubling($value);
        }
    }

    protected static function doubling($value)
    {
        $codes  = array_map('ord', str_split($value));
        $binary = vsprintf(str_repeat("%08b", strlen($value)), $codes);
        $codes  = array_map('bindec', str_split(substr($binary, 1) . '0', 8));

        // Make this method resilient against timing attacks
        if (ord($value[0]) & 0x80) {
            $codes[15] ^= 0x87;
        } else {
            $codes[15] ^= 0x0;
        }

        return implode('', array_map('chr', $codes));
    }

    public function offsetExists($offset)
    {
        return isset($this->values[$offset]);
    }

    public function offsetGet($offset)
    {
        return isset($this->values[$offset]) ? $this->values[$offset] : null;
    }

    public function offsetSet($offset, $value)
    {
        throw new \RuntimeException('Cannot set offset');
    }

    public function offsetUnset($offset)
    {
        throw new \RuntimeException('Cannot unset offset');
    }
}
