<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;

/**
 * Interface for Message Authentication Codes.
 */
abstract class MacInterface
{
    /// \internal Flag indicating whether this context is expired or not
    private $finished = false;

    /**
     * Construct a new context to generate a Message Authentication Code.
     *
     * \param MacEnum $macAlgorithm
     *      Algorithm to use to produce the message authentication code.
     *
     * \param SubAlgorithmAbstractEnum $innerAlgorithm
     *      Inner algorithm used during generation.
     *      This should be either an instance of CipherEnum or MacEnum,
     *      depending on the value for the \a $macAlgorithm parameter.
     *
     *      \warning
     *          For MAC algorithms that use ciphers, the cipher must be
     *          configured to use the Electronic Codebook (ECB) mode.
     *          Other modes of operations will result in garbage output.
     *
     * \param string $key
     *      Secret key used to produce the Message Authentication Code.
     *
     * \param string $nonce
     *      (optional) Nonce used to randomize the output.
     *
     *      \note
     *          Not all MAC algorithms make use of this parameter.
     */
    abstract public function __construct(
        MacEnum $macAlgorithm,
        SubAlgorithmAbstractEnum $innerAlgorithm,
        $key,
        $nonce = ''
    );

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
     *      Additional data to include
     *      in the Message Authentication Code.
     *
     * \retval object
     *      Returns this instance.
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
        return $this;
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
            throw new \RuntimeException('Cannot update expired context');
        }

        $this->finished = true;
        $res = $this->internalFinish();
        return $raw ? $res : bin2hex($res);
    }

    /**
     * All-in-one function to quickly compute
     * the message authentication code for a string of text.
     *
     * \param MacEnum $macAlgorithm
     *      Algorithm to use to produce the message authentication code.
     *
     * \param SubAlgorithmAbstractEnum $innerAlgorithm
     *      Inner algorithm used during generation.
     *      This should be either an instance of CipherEnum or MacEnum,
     *      depending on the value for the \a $macAlgorithm parameter.
     *
     * \param string $key
     *      Secret key used to produce the Message Authentication Code.
     *
     * \param string $data
     *      Data for which a message authentication code will be
     *      generated.
     *
     * \param string $nonce
     *      (optional) Nonce used to randomize the output.
     *
     *      \note
     *          Not all MAC algorithms make use of this parameter.
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
        return $obj->finish($raw);
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
        return $obj->finish(false);
    }
}
