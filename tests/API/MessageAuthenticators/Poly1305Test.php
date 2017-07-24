<?php

namespace fpoirotte\Cryptal\Tests\API\MessageAuthenticators;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\DefaultAlgorithms\Poly1305;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\MacEnum;

class Poly1305Test extends TestCase
{
    public function vectors()
    {
        return array(
            // These test vectors come from section 7 of
            // http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
            array(
                '0000000000000000000000000000000000000000000000000000000000000000',
                '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
                '49ec78090e481ec6c26b33b91ccc0307',
            ),
            array(
                '48656c6c6f20776f726c6421',
                '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
                'a6f745008f81c916a20dcc74eef2b2f0',
            ),

            // Test vector from section 2.5.1 of
            // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-06
            array(
                '43727970746f6772617068696320466f72756d2052657365617263682047726f7570',
                '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
                'a8061dc1305136c6c22b8baf0c0127a9',
            ),
        );
    }

    /**
     * @dataProvider vectors
     */
    public function test_Poly1305_message_authenticator($data, $key, $mac)
    {
        $key    = pack('H*', $key);
        $data   = pack('H*', $data);

        // Stream-based MAC
        $impl   = new Poly1305(MacEnum::MAC_POLY1305(), CipherEnum::CIPHER_AES_128(), $key);
        $impl->update($data);
        $res    = bin2hex($impl->finish(true));
        $this->assertSame($mac, $res);

        // All-in-one MAC method
        $this->assertSame($mac, Poly1305::mac(MacEnum::MAC_POLY1305(), CipherEnum::CIPHER_AES_128(), $key, $data, '', false));
    }
}
