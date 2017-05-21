<?php

namespace fpoirotte\Cryptal\Implementers;

/**
 * Interface for Message Authentication Codes.
 */
abstract class MacInterface
{
    /// \internal Flag indicating whether this context is expired or not
    private $finished = false;

    /// Keyed-hash MAC
    const MAC_HMAC  = 1;

    /// Block-cipher-based MAC
    const MAC_CMAC  = 2;

    /// Alias for MacInterface::MAC_CMAC
    const MAC_OMAC1 = self::MAC_CMAC;

    /// Parallelizable MAC
    const MAC_PMAC  = 3;

    /**
     * Construct a new context to generate a Message Authentication Code.
     *
     * \param opaque $macAlgorithm
     *      One of the \c MAC_* constants, representing the algorithm
     *      to use to produce the message authentication code.
     *
     * \param object $innerAlgorithm
     *      Either an instance of CryptoInterface or HashInterface,
     *      depending on the value for the \a $macAlgorithm parameter.
     *
     * \param string $key
     *      Secret key used to produce the Message Authentication Code.
     */
    abstract public function __construct($macAlgorithm, object $innerAlgorithm, $key);

    /// \copydoc MacInterface::update
    abstract protected function internalUpdate($data);

    /**
     * Finalize the computation and return the computed
     * Message Authentication Code in raw form.
     *
     * \retval string
     *      Raw Message Authentication Code (binary form).
     */
    abstract protected function internalFinish();

    /**
     * Update the internal state using the given data.
     *
     * \param string $data
     *      Additional data to include
     *      in the Message Authentication Code.
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
     * Message Authentication Code.
     *
     * \param bool $raw
     *      (optional) Whether the result should be returned
     *      in its raw form (\c true) or using its hexadecimal
     *      representation (\c false).
     *      Defaults to \c false.
     *
     * \retval string
     *      Message Authentication Code.
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
     * the message authentication code for a string of text.
     *
     * \param opaque $macAlgorithm
     *      One of the \c MAC_* constants, representing the algorithm
     *      to use to produce the message authentication code.
     *
     * \param object $innerAlgorithm
     *      Either an instance of CryptoInterface or HashInterface,
     *      depending on the value for the \a $macAlgorithm parameter.
     *
     * \param string $key
     *      Secret key used to produce the Message Authentication Code.
     *
     * \param string $data
     *      Data for which a message authentication code will be
     *      generated.
     *
     * \param bool $raw
     *      (optional) Whether the result should be returned
     *      in raw form (\c true) or using its hexadecimal
     *      representation (\c false).
     *      Defaults to \c false.
     *
     * \retval string
     *      Message Authentication Code for the given data.
     */
    final public static function mac($macAlgorithm, object $innerAlgorithm, $key, $data, $raw = false)
    {
        $obj = new static($algorithm, $key);
        $obj->update($data);
        return $obj->finish($raw);
    }
}
