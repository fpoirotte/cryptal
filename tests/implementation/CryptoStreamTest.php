<?php

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;

class CryptoStreamTest extends TestCase
{
    protected $ctx;

    public function setUp()
    {
        // Initialize the library.
        \fpoirotte\Cryptal::init();
        try {
            Registry::buildCipher(CipherEnum::CIPHER_AES_128(), ModeEnum::MODE_ECB(), new None, 'abcdabcdabcdabcd', 0, true);
        } catch (\Exception $e) {
            $this->markTestSkipped('No available AES implementation');
        }
    }

    public function provider()
    {
        // We use AES-128 to test the stream wrapper because it is assumed
        // most (all?) implementations support it.
        //
        // These test vectors come from appendix F of
        // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        // These were preferred over other accessible test vectors
        // because they all use the same key & multi-block plaintext
        // (and most of them share the same IV as well).
        return array(
            'aes-128-cbc' => array(
                'cbc',
                '000102030405060708090a0b0c0d0e0f',
                '7649abac8119b246cee98e9b12e9197d' .
                '5086cb9b507219ee95db113a917678b2' .
                '73bed6b8e3c1743b7116e69e22229516' .
                '3ff1caa1681fac09120eca307586e1a7'
            ),
            'aes-128-cfb' => array(
                'cfb',
                '000102030405060708090a0b0c0d0e0f',
                '3b3fd92eb72dad20333449f8e83cfb4a' .
                'c8a64537a0b3a93fcde3cdad9f1ce58b' .
                '26751f67a3cbb140b1808cf187a4f4df' .
                'c04b05357c5d1c0eeac4c66f9ff7f2e6'
            ),
            'aes-128-ctr' => array(
                'ctr',
                'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
                '874d6191b620e3261bef6864990db6ce' .
                '9806f66b7970fdff8617187bb9fffdff' .
                '5ae4df3edbd5d35e5b4f09020db03eab' .
                '1e031dda2fbe03d1792170a0f3009cee'
            ),
            'aes-128-ecb' => array(
                'ecb',
                '000102030405060708090a0b0c0d0e0f',
                '3ad77bb40d7a3660a89ecaf32466ef97' .
                'f5d3d58503b9699de785895a96fdbaaf' .
                '43b1cd7f598ece23881b00e3ed030688' .
                '7b0c785e27e8ad3f8223207104725dd4'
            ),
            'aes-128-ofb' => array(
                'ofb',
                '000102030405060708090a0b0c0d0e0f',
                '3b3fd92eb72dad20333449f8e83cfb4a' .
                '7789508d16918f03f53c52dac54ed825' .
                '9740051e9c5fecf64344f7a82260edcc' .
                '304c6528f659c77866a510d9c1d6ae5e'
            ),
        );
    }

    /**
     * @dataProvider provider
     */
    public function testStream($mode, $iv, $expected)
    {
        $plaintext =    '6bc1bee22e409f96e93d7e117393172a' .
                        'ae2d8a571e03ac9c9eb76fac45af8e51' .
                        '30c81c46a35ce411e5fbc1191a0a52ef' .
                        'f69f2445df4f9b17ad2b417be66c3710';

        $ctx = stream_context_create(
            array(
                'cryptal' => array(
                    'key'       => pack('H*', '2b7e151628aed2a6abf7158809cf4f3c'),
                    'IV'        => pack('H*', $iv),
                )
            )
        );

        $encrypt = fopen("cryptal.encrypt://$mode/aes_128", 'w+', false, $ctx);
        fwrite($encrypt, pack('H*', $plaintext));
        fflush($encrypt);

        $ciphertext = '';
        while ($data = fread($encrypt, 1024)) {
            $ciphertext .= $data;
        }
        $this->assertSame($expected, bin2hex($ciphertext));

        $decrypt = fopen("cryptal.decrypt://$mode/aes_128", 'w+', false, $ctx);
        fwrite($decrypt, $ciphertext);
        fflush($decrypt);
        $plaintext2 = '';
        while ($data = fread($decrypt, 1024)) {
            $plaintext2 .= $data;
        }
        $this->assertSame($plaintext, bin2hex($plaintext2));
    }
}
