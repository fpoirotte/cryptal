<?php

namespace fpoirotte\Cryptal\Padding;

use fpoirotte\Cryptal\PaddingInterface;

/**
 * No padding at all.
 *
 * This means that the input data is already expected
 * to have a size that is a multiple of the block size.
 * Do not use this class unless you know what you are doing.
 */
class None implements PaddingInterface
{
    public function getPaddingData($blockSize, $expectedSize)
    {
        return '';
    }

    public function getPaddingSize($paddedData, $blockSize)
    {
        return 0;
    }
}
