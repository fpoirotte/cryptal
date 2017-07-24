<?php

namespace fpoirotte\Cryptal\Tests\API\Misc;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\Implementers\HashInterface;
use fpoirotte\Cryptal\Implementers\MacInterface;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\MacEnum;

abstract class Hash extends HashInterface
{
    public function __construct(HashEnum $algo)
    {
    }
}

abstract class Mac extends MacInterface
{
    public function __construct(MacEnum $algo, SubAlgorithmAbstractEnum $subAlgo, $key, $nonce = '')
    {
    }
}

class RegistryTest extends TestCase
{
    public function setUp()
    {
        $cipher = $this->getMockBuilder('fpoirotte\\Cryptal\\Implementers\\CryptoInterface')->getMock();
        $hash   = $this->getMockBuilder('fpoirotte\\Cryptal\\Tests\\API\\Misc\\Hash')->disableOriginalConstructor()->getMock();
        $mac    = $this->getMockBuilder('fpoirotte\\Cryptal\\Tests\\API\\Misc\\Mac')->disableOriginalConstructor()->getMock();

        $registry = Registry::getInstance();
        $registry->reset();
        $registry->addCipher('fpoirotte/cryptal', get_class($cipher), CipherEnum::CIPHER_AES_128(), ModeEnum::MODE_ECB(), ImplementationTypeEnum::TYPE_USERLAND());
        $registry->addHash('fpoirotte/cryptal', get_class($hash), HashEnum::HASH_MD5(), ImplementationTypeEnum::TYPE_USERLAND());
        $registry->addMac('fpoirotte/cryptal', get_class($mac), MacEnum::MAC_HMAC(), ImplementationTypeEnum::TYPE_USERLAND());
        $registry->addMac('fpoirotte/cryptal', get_class($mac), MacEnum::MAC_CMAC(), ImplementationTypeEnum::TYPE_USERLAND());

        $this->registry = $registry;
    }

    public function tearDown()
    {
        $this->registry->reset();
    }

    public function testAlgorithmsRetrieval()
    {
        $expectedCiphers = array(
            array(CipherEnum::CIPHER_AES_128(), ModeEnum::MODE_ECB())
        );
        $ciphers = $this->registry->getSupportedCiphers();
        $this->assertEquals($expectedCiphers, $ciphers);

        $hashes = $this->registry->getSupportedHashes();
        $this->assertEquals(array(HashEnum::HASH_MD5()), $hashes);

        $macs = $this->registry->getSupportedMacs();
        $this->assertEquals(array(MacEnum::MAC_HMAC(), MacEnum::MAC_CMAC()), $macs);
    }

    public function testEmptying()
    {
        $this->registry->reset();

        $ciphers = $this->registry->getSupportedCiphers();
        $this->assertEquals(array(), $ciphers);

        $hashes = $this->registry->getSupportedHashes();
        $this->assertEquals(array(), $hashes);

        $macs = $this->registry->getSupportedMacs();
        $this->assertEquals(array(), $macs);
    }

    public function testFactories()
    {
        $res = $this->registry->buildCipher(CipherEnum::CIPHER_AES_128(), ModeEnum::MODE_ECB(), new None(), 'secret_k', 0, true);
        $this->assertInstanceOf('fpoirotte\\Cryptal\\Implementers\\CryptoInterface', $res);

        $res = $this->registry->buildHash(HashEnum::HASH_MD5(), true);
        $this->assertInstanceOf('fpoirotte\\Cryptal\\Implementers\\HashInterface', $res);

        // HMAC-MD5
        $res = $this->registry->buildMac(MacEnum::MAC_HMAC(), HashEnum::HASH_MD5(), 'testtesttesttest', '', true);
        $this->assertInstanceOf('fpoirotte\\Cryptal\\Implementers\\MacInterface', $res);

        // CMAC-AES128
        $res = $this->registry->buildMac(MacEnum::MAC_CMAC(), CipherEnum::CIPHER_AES_128(), 'testtesttesttest', '', true);
        $this->assertInstanceOf('fpoirotte\\Cryptal\\Implementers\\MacInterface', $res);
    }

    /**
     * @expectedException           Exception
     * @expectedExceptionMessage    No safe implementation found
     */
    public function testUnsafeCipherFactory()
    {
        $this->registry->buildCipher(CipherEnum::CIPHER_AES_128(), ModeEnum::MODE_ECB(), new None(), 'secret_k');
    }

    /**
     * @expectedException           Exception
     * @expectedExceptionMessage    No safe implementation found
     */
    public function testUnsafeHashFactory()
    {
        $this->registry->buildHash(HashEnum::HASH_MD5());
    }

    /**
     * @expectedException           Exception
     * @expectedExceptionMessage    No safe implementation found
     */
    public function testUnsafeMacFactory()
    {
        $this->registry->buildMac(MacEnum::MAC_HMAC(), HashEnum::HASH_MD5(), 'testtesttesttest');
    }
}
