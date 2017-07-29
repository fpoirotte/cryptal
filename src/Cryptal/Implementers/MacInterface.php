<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;
use fpoirotte\Cryptal\ContextBasedInterface;
use fpoirotte\Cryptal\MacEnum;

interface MacInterface extends ContextBasedInterface
{
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
    public function __construct(
        MacEnum $macAlgorithm,
        SubAlgorithmAbstractEnum $innerAlgorithm,
        $key,
        $nonce = ''
    );

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
    public static function mac(
        MacEnum $macAlgorithm,
        SubAlgorithmAbstractEnum $innerAlgorithm,
        $key,
        $data,
        $nonce = '',
        $raw = false
    );
}
