<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\Implementers\MacInterface;
use fpoirotte\Cryptal\AbstractContextBasedAlgorithm;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;
use fpoirotte\Cryptal\MacEnum;

/**
 * Interface for Message Authentication Codes.
 */
abstract class AbstractMac extends AbstractContextBasedAlgorithm implements MacInterface
{
    final public static function mac(
        MacEnum $macAlgorithm,
        SubAlgorithmAbstractEnum $innerAlgorithm,
        $key,
        $data,
        $nonce = '',
        $raw = false
    ) {
        $obj = new static($macAlgorithm, $innerAlgorithm, $key, $nonce);
        $obj->update($data);
        return $obj->finalize($raw);
    }
}
