<?php

namespace fpoirotte\Cryptal\Implementers;

/**
 * Interface for hashes/digests.
 */
abstract class HashInterface
{
    private $finished = false;

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
