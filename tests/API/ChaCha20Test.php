<?php

namespace fpoirotte\Cryptal\Tests\API;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\DefaultAlgorithms\ChaCha20;
use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;

/**
 * Test vectors for ChaCha20.
 */
class ChaCha20Test extends TestCase
{
    public function vectors()
    {
        return array(
            // From section A.2 of https://tools.ietf.org/html/rfc7539
            array(
                '0000000000000000000000000000000000000000000000000000000000000000',
                '000000000000000000000000',
                '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc' .
                '8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c' .
                'c387b669b2ee6586',
            ),
        );
    }

    /**
     * @dataProvider vectors
     */
    public function test_Chacha20_cipher($key, $nonce, $ciphertext)
    {
        $key        = pack('H*', $key);
        $nonce      = pack('H*', $nonce);
        $ciphertext = pack('H*', $ciphertext);

        $cipher     = new ChaCha20(CipherEnum::CIPHER_CHACHA20(), ModeEnum::MODE_ECB(), new None, $key, 0);
        $plain      = str_repeat("\x00", strlen($ciphertext));
        $this->assertSame($ciphertext, $cipher->encrypt($nonce, $plain));
    }
}
