<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\SubAlgorithmInterface;
use fpoirotte\Cryptal\ContextBasedInterface;
use fpoirotte\Cryptal\HashEnum;

interface HashInterface extends ContextBasedInterface, SubAlgorithmInterface
{
    /**
     * Construct a new hashing context.
     *
     * \param HashEnum $algorithm
     *      Algorithm to use to produce the hash/message digest.
     */
    public function __construct(HashEnum $algorithm);

    /**
     * All-in-one function to quickly compute
     * the hash/message digest for a string of text.
     *
     * \param HashEnum $algorithm
     *      Algorithm to use to produce the hash/message digest.
     *
     * \param string $data
     *      Data to hash.
     *
     * \param bool $raw
     *      (optional) Whether the result should be returned
     *      in raw form (\c true) or using its hexadecimal
     *      representation (\c false).
     *      Defaults to \c false.
     *
     * \retval string
     *      Hash/message digest for the given data.
     */
    public static function hash(HashEnum $algorithm, $data, $raw = false);
}
