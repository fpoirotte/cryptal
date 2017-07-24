<?php

namespace fpoirotte\Cryptal\Tests\API\AEAD;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\DefaultAlgorithms\ChaCha20;
use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;

/**
 * Test vectors for ChaCha20.
 */
class ChaCha20Poly1305Test extends TestCase
{
    public function vectors()
    {
        return array(
            // From section 2.8.2 of https://tools.ietf.org/html/rfc7539
            '(RFC 7539)' => array(
                '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
                '070000004041424344454647',
                '4c616469657320616e642047656e746c656d656e206f662074686520636c6173' .
                '73206f66202739393a204966204920636f756c64206f6666657220796f75206f' .
                '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73' .
                '637265656e20776f756c642062652069742e',
                '50515253c0c1c2c3c4c5c6c7',
                'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' .
                '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' .
                '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' .
                '3ff4def08e4b7a9de576d26586cec64b6116',
                '1ae10b594f09e26a7e902ecbd0600691',
            ),
        );
    }

    /**
     * @dataProvider vectors
     */
    public function testChaCha20_Poly1305_AEAD($key, $nonce, $plaintext, $ad, $ciphertext, $tag)
    {
        $key        = pack('H*', $key);
        $nonce      = pack('H*', $nonce);
        $plaintext  = pack('H*', $plaintext);
        $ad         = pack('H*', $ad);

        $cipher     = new ChaCha20(CipherEnum::CIPHER_CHACHA20(), ModeEnum::MODE_ECB(), new None, $key);
        $outTag     = '';
        $res        = $cipher->encrypt($nonce, $plaintext, $outTag, $ad);
        $this->assertSame($ciphertext, bin2hex($res));
        $this->assertSame($tag, bin2hex($outTag));

        $res        = $cipher->decrypt($nonce, $res, $outTag, $ad);
        $this->assertSame(bin2hex($plaintext), bin2hex($res));
    }
}
