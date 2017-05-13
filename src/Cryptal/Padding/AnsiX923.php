<?php

namespace fpoirotte\Cryptal\Padding;

use fpoirotte\Cryptal\PaddingInterface;

/// Pads a string using the scheme defined in ANSI X.923.
class AnsiX923 implements PaddingInterface
{
    public function getPaddingData($blockSize, $expectedSize)
    {
        return str_repeat("\x00", $expectedSize - 1) . chr($expectedSize);
    }

    public function getPaddingSize($paddedData, $blockSize)
    {
        $len = strlen($paddedData);
        if (!$len) {
            throw new \Exception('Invalid data');
        }

        $padLen = ord($paddedData[$len - 1]);

        // Make sure all bytes marked as padding are NUL bytes.
        if ($padLen - 1 !== strspn($paddedData, "\x00", -$padLen, -1)) {
            throw new \Exception('Invalid data');
        }

        return $padLen;
    }
}
