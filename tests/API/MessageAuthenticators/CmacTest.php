<?php

namespace fpoirotte\Cryptal\Tests\API\MessageAuthenticators;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\DefaultAlgorithms\Cmac;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\MacEnum;

class CmacTest extends TestCase
{
    public function setUp()
    {
        $registry = Registry::getInstance();
        $registry->addCipher(
            '',
            '\\fpoirotte\\Cryptal\\Tests\\AesEcbStub',
            CipherEnum::CIPHER_AES_128(),
            ModeEnum::MODE_ECB(),
            ImplementationTypeEnum::TYPE_USERLAND()
        );
    }

    public function provider()
    {
        // See http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/tv/omac1-tv.txt
        $key  = '2b7e151628aed2a6abf7158809cf4f3c';
        $data = '6bc1bee22e409f96e93d7e117393172a' .
                'ae2d8a571e03ac9c9eb76fac45af8e51' .
                '30c81c46a35ce411e5fbc1191a0a52ef' .
                'f69f2445df4f9b17ad2b417be66c3710';

        return array(
            // key, data, mac
            array($key, substr($data, 0,  0*2), 'bb1d6929e95937287fa37d129b756746'),
            array($key, substr($data, 0, 16*2), '070a16b46b4d4144f79bdd9dd04a287c'),
            array($key, substr($data, 0, 40*2), 'dfa66747de9ae63030ca32611497c827'),
            array($key, substr($data, 0, 64*2), '51f0bebf7e3b9d92fc49741779363cfe'),
        );
    }

    /**
     * @dataProvider provider
     */
    public function test_CMAC_message_authenticator($key, $data, $mac)
    {
        $key    = pack('H*', $key);
        $data   = pack('H*', (string) $data);

        // Stream-based MAC
        $impl   = new Cmac(MacEnum::MAC_CMAC(), CipherEnum::CIPHER_AES_128(), $key);
        $impl->update($data);
        $res    = bin2hex($impl->finalize(true));
        $this->assertSame($mac, $res);

        // All-in-one MAC method
        $this->assertSame($mac, Cmac::mac(MacEnum::MAC_CMAC(), CipherEnum::CIPHER_AES_128(), $key, $data, '', false));
    }
}
