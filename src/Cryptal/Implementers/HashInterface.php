<?php

namespace fpoirotte\Cryptal\Implementers;

/**
 * Interface for hashes/message digests.
 */
abstract class HashInterface
{
    /// \internal Flag indicating whether this context is expired or not
    private $finished = false;

    /// Cyclic Redundancy Check (from ITU V.42; 32 bit little-endian hashes)
    const HASH_CRC32        = 1;

    /// Message Digest 2 (128 bit hashes)
    const HASH_MD2          = 2;

    /// Message Digest 4 (128 bit hashes)
    const HASH_MD4          = 3;

    /// Message Digest 5 (128 bit hashes)
    const HASH_MD5          = 4;

    /// Secure Hash Algorithm 1 (160 bit hashes)
    const HASH_SHA1         = 5;

    /// RACE Integrity Primitives Evaluation Message Digest (160 bit hashes)
    const HASH_RIPEMD160    = 6;

    /// Secure Hash Algorithm 2 (224 bit hashes)
    const HASH_SHA224       = 7;

    /// Secure Hash Algorithm 2 (256 bit hashes)
    const HASH_SHA256       = 8;

    /// Secure Hash Algorithm 2 (384 bit hashes)
    const HASH_SHA384       = 9;

    /// Secure Hash Algorithm 2 (512 bit hashes)
    const HASH_SHA512       = 10;


    /**
     * Construct a new hashing context.
     *
     * \param opaque $algorithm
     *      One of the \c HASH_* constants, representing the algorithm
     *      to use to produce the hash/message digest.
     */
    abstract public function __construct($algorithm);

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

    /**
     * Update the internal state using the given data.
     *
     * \param string $data
     *      Additional data to hash.
     */
    final public function update($data)
    {
        if ($this->finished) {
            throw \RuntimeError('Cannot update expired context');
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
            throw \RuntimeError('Cannot update expired context');
        }

        $this->finished = true;
        $res = $this->internalFinish();
        return $raw ? $res : bin2hex($res);
    }

    /**
     * All-in-one function to quickly compute
     * the hash/message digest for a string of text.
     *
     * \param opaque $algorithm
     *      One of the \c HASH_* constants, representing the algorithm
     *      to use to produce the hash/message digest.
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
    final public static function hash($algorithm, $data, $raw = false)
    {
        $obj = new static($algorithm);
        $obj->update($data);
        return $obj->finish($raw);
    }
}
