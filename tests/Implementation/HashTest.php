<?php

namespace fpoirotte\Cryptal\Tests\Implementation;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\Registry;

class HashTest extends TestCase
{
    public function setUp()
    {
        // Initialize the library.
        \fpoirotte\Cryptal::init();
    }

    public function provider()
    {
        // Run a few tests against known test vectors.
        //
        // We use MD5 & SHA-1 as they are algorithms supported
        // by most hashing libraries.
        //
        // We do not need to run a lot of tests here, as we are not aiming
        // at testing the hashing code itself, but the interface for doing so.
        return array(
            // From RFC 1321
            'MD5 #1'    => array(HashEnum::HASH_MD5(), '', 'd41d8cd98f00b204e9800998ecf8427e'),
            'MD5 #2'    => array(HashEnum::HASH_MD5(), 'a', '0cc175b9c0f1b6a831c399e269772661'),
            'MD5 #3'    => array(
                HashEnum::HASH_MD5(),
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                'd174ab98d277d9f5a5611c2c9f419d9f'
            ),

            // From NIST CAVS
            'SHA-1 #1'  => array(HashEnum::HASH_SHA1(), '', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
            'SHA-1 #2'  => array(HashEnum::HASH_SHA1(), "\xa8", '99f2aa95e36f95c2acb0eaf23998f030638f3f15'),
            'SHA-1 #3'  => array(
                HashEnum::HASH_SHA1(),
                "\xb5\xc1\xc6\xf1\xaf",
                'fec9deebfcdedaf66dda525e1be43597a73a1f93'
            ),
        );
    }

    /**
     * @dataProvider provider
     */
    public function testMessageDigestWith($algo, $data, $expected)
    {
        try {
            $impl   = Registry::buildHash($algo, true);
            $result = $impl->update($data)->finalize(false);
        } catch (\Exception $e) {
            $this->markTestSkipped((string) $e);
        }
        $this->assertSame($expected, $result);
    }
}
