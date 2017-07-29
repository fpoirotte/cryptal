<?php

namespace fpoirotte\Cryptal;

interface ContextBasedInterface
{
    /**
     * Update the internal state using the given data.
     *
     * \param string $data
     *      Additional data to process.
     *
     * \retval object
     *      Returns this instance.
     */
    public function update($data);

    /**
     * Finalize the computation and return the resulting value.
     *
     * \param bool $raw
     *      (optional) Whether the result should be returned
     *      in its raw form (\c true) or using its hexadecimal
     *      representation (\c false).
     *      Defaults to \c false.
     *
     * \retval string
     *      Value resulting from the computation.
     */
    public function finalize($raw = false);

    /**
     * Finalize the computation using the current context and return
     * the value resulting from the computation, in hexadecimal form.
     *
     * \retval string
     *      Value resulting from the computation.
     */
    public function __toString();
}
