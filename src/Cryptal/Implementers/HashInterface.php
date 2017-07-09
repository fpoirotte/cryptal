<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\SubAlgorithmInterface;
use fpoirotte\Cryptal\HashEnum;

/**
 * Interface for hashes/message digests.
 */
abstract class HashInterface implements SubAlgorithmInterface
{
    /// \internal Flag indicating whether this context is expired or not
    private $finished = false;

    /**
     * Construct a new hashing context.
     *
     * \param HashEnum $algorithm
     *      Algorithm to use to produce the hash/message digest.
     */
    abstract public function __construct(HashEnum $algorithm);

    /// \copydoc HashInterface::update
    abstract protected function internalUpdate($data);

    /**
     * Finalize the computation and return the computed
     * hash/message digest in raw form.
     *
     * \retval string
     *      Raw hash value (binary form).
     */
    abstract protected function internalFinish();

    /// Clone this context.
    public function __clone()
    {
        // By default, we do nothing.
        // Subclasses SHOULD redefine this method if specific handling
        // is necessary to make the clone work properly.
    }

    /**
     * Update the internal state using the given data.
     *
     * \param string $data
     *      Additional data to hash.
     */
    final public function update($data)
    {
        if ($this->finished) {
            throw new \RuntimeException('Cannot update expired context');
        }

        if (!is_string($data)) {
            throw new \InvalidArgumentException('Invalid data');
        }

        $this->internalUpdate($data);
    }

    /**
     * Finalize the computation and return the computed
     * hash/message digest.
     *
     * \param bool $raw
     *      (optional) Whether the result should be returned
     *      in its raw form (\c true) or using its hexadecimal
     *      representation (\c false).
     *      Defaults to \c false.
     *
     * \retval string
     *      Hash/message digest.
     *
     * \note
     *      Once this method has been called, the context
     *      is marked as expired and can no longer be used.
     *      Trying to reuse an expired context will result
     *      in an error.
     */
    final public function finish($raw = false)
    {
        if ($this->finished) {
            throw new \RuntimeException('Cannot update expired context');
        }

        $this->finished = true;
        $res = $this->internalFinish();
        return $raw ? $res : bin2hex($res);
    }

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
    final public static function hash(HashEnum $algorithm, $data, $raw = false)
    {
        $obj = new static($algorithm);
        $obj->update($data);
        return $obj->finish($raw);
    }

    /**
     * Return the hash associated with the current context,
     * in hexadecimal form.
     *
     * \retval string
     *      Hash
     */
    final public function __toString()
    {
        // We clone the object first, to make sure
        // it is still usable after this call.
        $obj = clone $this;
        return $obj->finish(false);
    }
}
