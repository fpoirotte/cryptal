<?php

namespace fpoirotte\Cryptal;

abstract class AbstractContextBasedAlgorithm
{
    /// \internal Flag indicating whether this context is expired or not
    private $finalized = false;

    /// \copydoc ContextBasedInterface::update
    abstract protected function internalUpdate($data);

    /**
     * Finalize the computation and return the computed
     * Message Authentication Code in raw form.
     *
     * \retval string
     *      Raw Message Authentication Code (binary form).
     */
    abstract protected function internalFinalize();

    final public function update($data)
    {
        if ($this->finalized) {
            throw new \RuntimeException('Cannot update an already-finalized context');
        }

        if (!is_string($data)) {
            throw new \InvalidArgumentException('Invalid data');
        }

        $this->internalUpdate($data);
        return $this;
    }

    /**
     * \copydoc ContextBasedInterface::finalize
     *
     * \note
     *      Once this method has been called, the context
     *      is marked as expired and can no longer be used.
     *      Trying to reuse an expired context will result
     *      in an error.
     */
    final public function finalize($raw = false)
    {
        if ($this->finalized) {
            throw new \RuntimeException('Cannot update an already-finalized context');
        }

        $this->finalized = true;
        $res = $this->internalFinalize();
        return $raw ? $res : bin2hex($res);
    }

    /**
     * Return the Message Authentication Code associated
     * with the current context, in hexadecimal form.
     *
     * \retval string
     *      Message Authentication Code
     */
    final public function __toString()
    {
        // We clone the object first, to make sure
        // it is still usable after this call.
        $obj = clone $this;
        return $obj->finalize(false);
    }
}
