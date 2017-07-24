<?php

namespace fpoirotte\Cryptal\Tests\Implementation;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\HashEnum;

class MacTest extends TestCase
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
        // We use HMAC-MD5 as this is supported by most libraries.
        // We do not need to run a lot of tests here, as we are not aiming
        // at testing the MAC-generation code itself, but the interface
        // for doing so.
        return array(
            // From RFC 2202
            'HMAC-MD5 #1'   => array(
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                'Hi There',
                "9294727a3638bb1c13f48ef8158bfc9d",
            ),
            'HMAC-MD5 #2'   => array(
                str_repeat('aa', 80),
                'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data',
                "6f630fad67cda0ee1fb1f562db3aa53e",
            ),
        );
    }

    /**
     * @dataProvider provider
     */
    public function testMessageAuthenticationWith($key, $data, $expected)
    {
        try {
            $mac = Registry::buildMac(MacEnum::MAC_HMAC(), HashEnum::HASH_MD5(), pack('H*', $key), '', true);
            $result = $mac->update($data)->finish(false);
        } catch (\Exception $e) {
            $this->markTestSkipped((string) $e);
        }
        $this->assertSame($expected, $result);
    }
}
