<?php

namespace fpoirotte\Cryptal\Padding;

use fpoirotte\Cryptal\PaddingInterface;

/// Pads a string using the scheme defined in ISO/IEC 7816-4.
class IsoIec7816 implements PaddingInterface
{
    public function getPaddingData($blockSize, $expectedSize)
    {
        return "\x80" . str_repeat("\x00", $expectedSize - 1);
    }

    public function getPaddingSize($paddedData, $blockSize)
    {
        $len = strlen($paddedData);
        if (!$len) {
            throw new \Exception('Invalid data');
        }

        for ($i = 1; $i < $blockSize && $i < $len && "\x00" === $paddedData[$len - $i]; $i++) {
            // Nothing to do
        }

        if ($i === $len) {
            // The entire string was made of NUL bytes
            throw new \Exception('Invalid data');
        }

        if ("\x80" !== $paddedData[$len - $i]) {
            throw new \Exception('Invalid data');
        }

        return $i;
    }
}
