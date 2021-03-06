<?php

namespace fpoirotte\Cryptal\Padding;

use fpoirotte\Cryptal\PaddingInterface;

/**
 * Pads a string using the scheme defined in ISO 10126.
 *
 * \note
 *      This padding scheme was withdrawn in 2007
 *      by the ISO standards committee.
 *      It is merely included here for interoperability.
 */
class Iso10126 implements PaddingInterface
{
    /**
     * Generate a bunch of pseudo-random bytes.
     *
     * \retval string
     *      A string consisting of pseudo-randomly generated bytes.
     */
    protected static function getRandomBytes()
    {
        // We do not need true randomness here, so we just
        // use uniqid() as it does not require any additional
        // extension. The same reasoning goes for md5().
        return md5(uniqid("", true), true);
    }

    public function getPaddingData($blockSize, $expectedSize)
    {
        $padding    = '';
        for ($i = $expectedSize; $i > 1; $i -= 16) {
            $padding .= static::getRandomBytes();
        }
        return ((string) substr($padding, 0, $expectedSize - 1)) . chr($expectedSize);
    }

    public function getPaddingSize($paddedData, $blockSize)
    {
        $len = strlen($paddedData);
        if (!$len) {
            throw new \Exception('Invalid data');
        }
        return ord($paddedData[$len - 1]);
    }
}
