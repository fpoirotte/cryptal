<?php

namespace fpoirotte\Cryptal\Implementers;

/**
 * Interface for Message Authentication Code.
 */
abstract class MacInterface
{
    private $finished = false;

    abstract public function __construct($algorithm, $key);

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

    final public static function mac($algorithm, $key, $data)
    {
        $obj = new static($algorithm, $key);
        $obj->update($data);
        return $obj->finish();
    }
}
