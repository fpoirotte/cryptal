<?php

namespace fpoirotte\Cryptal\Tests\API\Misc;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Padding\Zero;
use fpoirotte\Cryptal\Padding\NonEmptyZero;
use fpoirotte\Cryptal\Padding\AnsiX923;
use fpoirotte\Cryptal\Padding\IsoIec7816;
use fpoirotte\Cryptal\Padding\Pkcs7;
use fpoirotte\Cryptal\Padding\None;

class Iso10126 extends \fpoirotte\Cryptal\Padding\Iso10126
{
    protected static function getRandomBytes()
    {
        return 'abcdef0123456789';
    }
}

class PaddingTest extends TestCase
{
    public function paddingProvider()
    {
        $none       = new None;
        $zero       = new Zero;
        $nezero     = new NonEmptyZero;
        $ansix923   = new AnsiX923;
        $iso10126   = new Iso10126;
        $pkcs7      = new Pkcs7;
        $iso7816    = new IsoIec7816;

        return array(
            'None #1' => array(1, $none, ''),
            'None #2' => array(2, $none, ''),
            'None #3' => array(3, $none, ''),
            'None #4' => array(4, $none, ''),

            'Zero #1' => array(1, $zero, "\x00"),
            'Zero #2' => array(2, $zero, "\x00\x00"),
            'Zero #3' => array(3, $zero, "\x00\x00\x00"),
            'Zero #4' => array(4, $zero, ''),

            'Non Empty Zero #1' => array(1, $nezero, "\x00"),
            'Non Empty Zero #2' => array(2, $nezero, "\x00\x00"),
            'Non Empty Zero #3' => array(3, $nezero, "\x00\x00\x00"),
            'Non Empty Zero #4' => array(4, $nezero, "\x00\x00\x00\x00"),

            'ANSI X.923 #1' => array(1, $ansix923, "\x01"),
            'ANSI X.923 #2' => array(2, $ansix923, "\x00\x02"),
            'ANSI X.923 #3' => array(3, $ansix923, "\x00\x00\x03"),
            'ANSI X.923 #4' => array(4, $ansix923, "\x00\x00\x00\x04"),

            'ISO 10126 #1' => array(1, $iso10126, "\x01"),
            'ISO 10126 #2' => array(2, $iso10126, "a\x02"),
            'ISO 10126 #3' => array(3, $iso10126, "ab\x03"),
            'ISO 10126 #4' => array(4, $iso10126, "abc\x04"),

            'PKCS#7 #1' => array(1, $pkcs7, "\x01"),
            'PKCS#7 #2' => array(2, $pkcs7, "\x02\x02"),
            'PKCS#7 #3' => array(3, $pkcs7, "\x03\x03\x03"),
            'PKCS#7 #4' => array(4, $pkcs7, "\x04\x04\x04\x04"),

            'ISO/IEC 7816-4 #1' => array(1, $iso7816, "\x80"),
            'ISO/IEC 7816-4 #2' => array(2, $iso7816, "\x80\x00"),
            'ISO/IEC 7816-4 #3' => array(3, $iso7816, "\x80\x00\x00"),
            'ISO/IEC 7816-4 #4' => array(4, $iso7816, "\x80\x00\x00\x00"),
        );
    }

    /**
     * @dataProvider paddingProvider
     */
    public function testPadding($bufferSize, $scheme, $expected)
    {
        $this->assertSame(
            bin2hex($expected),
            bin2hex($scheme->getPaddingData(4, $bufferSize))
        );
    }
}
