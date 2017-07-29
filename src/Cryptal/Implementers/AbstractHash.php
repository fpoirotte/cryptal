<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\Implementers\HashInterface;
use fpoirotte\Cryptal\AbstractContextBasedAlgorithm;
use fpoirotte\Cryptal\HashEnum;

/**
 * Interface for hashes/message digests.
 */
abstract class AbstractHash extends AbstractContextBasedAlgorithm implements HashInterface
{
    final public static function hash(HashEnum $algorithm, $data, $raw = false)
    {
        $obj = new static($algorithm);
        return $obj->update($data)->finalize($raw);
    }
}
