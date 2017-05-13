<?php

namespace fpoirotte\Cryptal;

interface PaddingInterface
{
    /**
     * Return padding data to form a complete block.
     *
     * \param int $blockSize
     *      The cipher's block size, in bytes.
     *
     * \param int $expectedSize
     *      The number of bytes expected to form a (possibly new)
     *      complete block. This value is always such that
     *      0 < \a $expectedSize <= \a $blockSize
     *
     * \retval string
     *      Padding data.
     */
    public function getPaddingData($blockSize, $expectedSize);

    /**
     * Return the size (in bytes) of the padding
     * in some already-padded data.
     *
     * \param string $paddedData
     *      The padded data to analyze.
     *
     * \param int $blockSize
     *      The cipher's block size, in bytes.
     *
     * \throw Exception
     *      An exception is thrown when the supplied data is invalid
     *      (was not padded using the currently-selected scheme).
     *
     * \warning
     *      Some padding schemes can generate ambiguous data,
     *      resulting in possible data loss while removing the padding.
     *      This method suffers from the same shortcomings.
     *      If possible, you should not rely on this method to determine
     *      the plaintext's length. Instead, you should retrieve it
     *      using other means (eg. out-of-band communications).
     */
    public function getPaddingSize($paddedData, $blockSize);
}
