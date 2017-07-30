<?php

namespace fpoirotte\Cryptal\Tests\API\Filters;

use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\Tests\AesBasedTestCase;

class CryptoTest extends AesBasedTestCase
{
    public function vectors()
    {
        $key        =   '2b7e151628aed2a6abf7158809cf4f3c';
        $plaintext  =   '6bc1bee22e409f96e93d7e117393172a' .
                        'ae2d8a571e03ac9c9eb76fac45af8e51' .
                        '30c81c46a35ce411e5fbc1191a0a52ef' .
                        'f69f2445df4f9b17ad2b417be66c3710';

        // These test vectors come from appendix F of
        // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        // These were preferred over other accessible test vectors
        // because they all use the same key & multi-block plaintext
        // (and most of them share the same IV as well).
        return array(
            'aes-128-cbc' => array(
                ModeEnum::MODE_CBC(),
                $plaintext,
                $key,
                '000102030405060708090a0b0c0d0e0f',
                '7649abac8119b246cee98e9b12e9197d' .
                '5086cb9b507219ee95db113a917678b2' .
                '73bed6b8e3c1743b7116e69e22229516' .
                '3ff1caa1681fac09120eca307586e1a7',
                '',
                '',
            ),
            'aes-128-cfb' => array(
                ModeEnum::MODE_CFB(),
                $plaintext,
                $key,
                '000102030405060708090a0b0c0d0e0f',
                '3b3fd92eb72dad20333449f8e83cfb4a' .
                'c8a64537a0b3a93fcde3cdad9f1ce58b' .
                '26751f67a3cbb140b1808cf187a4f4df' .
                'c04b05357c5d1c0eeac4c66f9ff7f2e6',
                '',
                '',
            ),
            'aes-128-ctr' => array(
                ModeEnum::MODE_CTR(),
                $plaintext,
                $key,
                'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
                '874d6191b620e3261bef6864990db6ce' .
                '9806f66b7970fdff8617187bb9fffdff' .
                '5ae4df3edbd5d35e5b4f09020db03eab' .
                '1e031dda2fbe03d1792170a0f3009cee',
                '',
                '',
            ),
            'aes-128-ecb' => array(
                ModeEnum::MODE_ECB(),
                $plaintext,
                $key,
                '000102030405060708090a0b0c0d0e0f',
                '3ad77bb40d7a3660a89ecaf32466ef97' .
                'f5d3d58503b9699de785895a96fdbaaf' .
                '43b1cd7f598ece23881b00e3ed030688' .
                '7b0c785e27e8ad3f8223207104725dd4',
                '',
                '',
            ),
            'aes-128-ofb' => array(
                ModeEnum::MODE_OFB(),
                $plaintext,
                $key,
                '000102030405060708090a0b0c0d0e0f',
                '3b3fd92eb72dad20333449f8e83cfb4a' .
                '7789508d16918f03f53c52dac54ed825' .
                '9740051e9c5fecf64344f7a82260edcc' .
                '304c6528f659c77866a510d9c1d6ae5e',
                '',
                '',
            ),
        );
    }

    /**
     * @dataProvider vectors
     */
    public function testFilterFor($mode, $plaintext, $key, $iv, $ciphertext, $aad, $tag)
    {
        $iv     = pack('H*', $iv);
        $key    = pack('H*', $key);

        // Test the encryption
        $stream     = fopen("php://memory", "w+b");
        stream_filter_append(
            $stream,
            'cryptal.encrypt',
            STREAM_FILTER_READ,
            array(
                // We use the default padding scheme (None)
                // and tag length (128 bits).
                'mode'          => $mode,
                'algorithm'     => CipherEnum::CIPHER_AES_128(),
                'iv'            => $iv,
                'key'           => $key,

                // We're using the stub which is based on PHP code
                'allowUnsafe'   => true,
            )
        );
        fwrite($stream, pack('H*', $plaintext));
        fseek($stream, 0, SEEK_SET);
        $this->assertSame($ciphertext, bin2hex(stream_get_contents($stream)));

        // And decryption too
        $stream     = fopen("php://memory", "w+b");
        stream_filter_append(
            $stream,
            'cryptal.decrypt',
            STREAM_FILTER_READ,
            array(
                // We use the default padding scheme (None)
                // and tag length (128 bits).
                'mode'          => $mode,
                'algorithm'     => CipherEnum::CIPHER_AES_128(),
                'iv'            => $iv,
                'key'           => $key,

                // We're using the AES stub, which is based on PHP code
                'allowUnsafe'   => true,
            )
        );
        fwrite($stream, pack('H*', $ciphertext));
        fseek($stream, 0, SEEK_SET);
        $this->assertSame($plaintext, bin2hex(stream_get_contents($stream)));
    }
}
