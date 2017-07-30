<?php

namespace fpoirotte\Cryptal\Tests;

use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\Registry;

abstract class AesBasedTestCase extends \PHPUnit\Framework\TestCase
{
    static $cache;

    public static function setUpBeforeClass()
    {
        self::$cache = array();

        $registry = Registry::getInstance();
        $registry->reset()->registerDefaultAlgorithms()->addCipher(
            '',
            '\\fpoirotte\\Cryptal\\Tests\\AesEcbStub',
            CipherEnum::CIPHER_AES_128(),
            ModeEnum::MODE_ECB(),
            ImplementationTypeEnum::TYPE_USERLAND()
        );
    }

    public static function tearDownAfterClass()
    {
        $registry = Registry::getInstance();
        $registry->reset()->load(true);
    }

    public function getCipher($key)
    {
        if (!isset(self::$cache[$key])) {
            $map = array(
                16  => CipherEnum::CIPHER_AES_128(),
                24  => CipherEnum::CIPHER_AES_192(),
                32  => CipherEnum::CIPHER_AES_256(),
            );
            $cipher = new AesEcbStub($map[strlen($key)], ModeEnum::MODE_ECB(), new None, $key);
            self::$cache[$key] = $cipher;
        }
        return self::$cache[$key];
    }
}
