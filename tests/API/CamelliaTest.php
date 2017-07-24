<?php

namespace fpoirotte\Cryptal\Tests\API;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\DefaultAlgorithms\Camellia;
use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;

/**
 * Test vectors for Camellia.
 */
class CamelliaTest extends TestCase
{
    public function vectors()
    {
        return array(
            // From section A of https://tools.ietf.org/html/rfc3713
            array(
                CipherEnum::CIPHER_CAMELIA_128(),
                '0123456789abcdeffedcba9876543210',
                '0123456789abcdeffedcba9876543210',
                '67673138549669730857065648eabe43',
            ),
            array(
                CipherEnum::CIPHER_CAMELIA_192(),
                '0123456789abcdeffedcba98765432100011223344556677',
                '0123456789abcdeffedcba9876543210',
                'b4993401b3e996f84ee5cee7d79b09b9',
            ),
            array(
                CipherEnum::CIPHER_CAMELIA_256(),
                '0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff',
                '0123456789abcdeffedcba9876543210',
                '9acc237dff16d76c20ef7c919e3a7509',
            ),
        );
    }

    /**
     * @dataProvider vectors
     */
    public function testCamelliaCipher($cipher, $key, $plaintext, $ciphertext)
    {
        $key        = pack('H*', $key);
        $plaintext  = pack('H*', $plaintext);
        $ciphertext = pack('H*', $ciphertext);

        $cipherObj  = new Camellia($cipher, ModeEnum::MODE_ECB(), new None, $key, 0);
        $this->assertSame(bin2hex($ciphertext), bin2hex($cipherObj->encrypt('', $plaintext)));
        $this->assertSame(bin2hex($plaintext), bin2hex($cipherObj->decrypt('', $ciphertext)));
    }
}
