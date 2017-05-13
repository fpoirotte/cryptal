<?php

namespace fpoirotte\Cryptal\Padding;

use fpoirotte\Cryptal\PaddingInterface;

/// Pads a string using the scheme defined in PKCS#7.
class Pkcs7 implements PaddingInterface
{
    public function getPaddingData($blockSize, $expectedSize)
    {
        return str_repeat(chr($expectedSize), $expectedSize);
    }

    public function getPaddingSize($paddedData, $blockSize)
    {
        $len = strlen($paddedData);
        if (!$len) {
            throw new \Exception('Invalid data');
        }

        $padLen = ord($paddedData[$len - 1]);

        // Make sure all bytes marked as padding are the same.
        if ($padLen - 1 !== strspn($paddedData, chr($padLen), -$padLen, -1)) {
            throw new \Exception('Invalid data');
        }

        return $padLen;
    }
}
