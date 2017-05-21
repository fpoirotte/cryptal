<?php

namespace fpoirotte\Cryptal\Implementers;

/**
 * Interface for hashes/message digests.
 */
abstract class HashInterface
{
    private $finished = false;

    const HASH_CRC32        = 1;
    const HASH_MD2          = 2;
    const HASH_MD4          = 3;
    const HASH_MD5          = 4;
    const HASH_SHA1         = 5;
    const HASH_RIPEMD160    = 6;
    const HASH_SHA224       = 7;
    const HASH_SHA256       = 8;
    const HASH_SHA384       = 9;
    const HASH_SHA512       = 10;

    abstract public function __construct($algorithm);

    abstract protected function internalUpdate($data);

    abstract protected function internalFinish();

    final public function update($data)
    {
        if ($this->finished) {
            throw \RuntimeError('Cannot update expired context');
        }

        $this->internalUpdate($data);
    }

    final public function finish()
    {
        $this->finished = true;
        return $this->internalFinish();
    }

    final public static function hash($algorithm, $data)
    {
        $obj = new static($algorithm);
        $obj->update($data);
        return $obj->finish();
    }
}
