<?php

namespace fpoirotte\Cryptal\Tests\API\MessageAuthenticators;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\DefaultAlgorithms\Umac;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\MacEnum;

class UmacTest extends TestCase
{
    protected static $aesStub = null;

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
        // See Appendix from https://fastcrypto.org/umac/rfc4418.txt
        $key    = bin2hex('abcdefghijklmnop');
        $abc500 = str_repeat('abc', 500);
        $nonce  = bin2hex('bcdefghi');

        return array(
            // key, nonce, data, 32-bit tag, 64-bit tag, 96-bit tag
            array($key, $nonce, '',         '113145FB', '6E155FAD26900BE1', '32FEDB100C79AD58F07FF764'),
            array($key, $nonce, 'aaa',      '3B91D102', '44B5CB542F220104', '185E4FE905CBA7BD85E4C2DC'),
            array($key, $nonce, 'abc',      'ABF3A3A0', 'D4D7B9F6BD4FBFCF', '883C3D4B97A61976FFCF2323'),
            array($key, $nonce, $abc500,    'ABEB3C8B', 'D4CF26DDEFD5C01A', '8824A260C53C66A36C9260A6'),
        );
    }

    /**
     * @dataProvider provider
     */
    public function test_UMAC_message_authenticator($key, $nonce, $data, $tag32, $tag64, $tag96)
    {
        $key    = pack('H*', $key);
        $nonce  = pack('H*', $nonce);

        $expectations = array(
            $tag32 => MacEnum::MAC_UMAC_32(),
            $tag64 => MacEnum::MAC_UMAC_64(),
            $tag96 => MacEnum::MAC_UMAC_96(),
        );

        foreach ($expectations as $mac => $algo) {
            $mac = strtolower($mac);

            // Stream-based MAC
            $impl   = new Umac($algo, CipherEnum::CIPHER_AES_128(), $key, $nonce);
            $impl->update($data);
            $res    = bin2hex($impl->finalize(true));
            $this->assertSame($mac, $res);

            // All-in-one MAC method
            $res = Umac::mac($algo, CipherEnum::CIPHER_AES_128(), $key, $data, $nonce, false);
            $this->assertSame($mac, $res);
        }

    }
}
