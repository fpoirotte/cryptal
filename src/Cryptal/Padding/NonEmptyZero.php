<?php

namespace fpoirotte\Cryptal\Padding;

use fpoirotte\Cryptal\PaddingInterface;

/**
 * Pads a string using NUL bytes, eventually creating a new block
 * if the plaintext's length is already a multiple of the block size.
 */
class NonEmptyZero implements PaddingInterface
{
    public function getPaddingData($blockSize, $expectedSize)
    {
        return str_repeat("\x00", $expectedSize);
    }

    public function getPaddingSize($paddedData, $blockSize)
    {
        // We could use strspn(strrev($paddedData), "\x00") instead,
        // but this would require additional memory allocations,
        // which is undesirable as $paddedData gets larger.
        $m = strlen($paddedData) - 1;
        for ($i = 0; $i <= $blockSize && $i <= $m && "\x00" === $paddedData[$m - $i]; $i++) {
            // Nothing to do
        }

        if (0 === $i) {
            // This should never happen.
            throw new \Exception('Invalid data');
        }

        return $i;
    }
}
