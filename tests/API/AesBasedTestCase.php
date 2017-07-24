<?php

namespace fpoirotte\Cryptal\Tests\API;

use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\CipherEnum;

abstract class AesBasedTestCase extends \PHPUnit\Framework\TestCase
{
    static $cache;

    public static function setUpBeforeClass()
    {
        self::$cache = array();
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
