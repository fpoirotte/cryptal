<?php

namespace fpoirotte\Cryptal\Tests\API\Filters;

use PHPUnit\Framework\TestCase;
use fpoirotte\Cryptal\HashEnum;

class HashTest extends TestCase
{
    public function vectors()
    {
        $data = "hello world!\n";
        return array(
            // Test vector generated using md5sum
            'MD5'   => array(HashEnum::HASH_MD5(),  $data, 'c897d1410af8f2c74fba11b1db511e9e'),
            // Test vector generated using sha1sum
            'SHA1'  => array(HashEnum::HASH_SHA1(), $data, 'f951b101989b2c3b7471710b4e78fc4dbdfa0ca6'),
        );
    }

    /**
     * @dataProvider vectors
     */
    public function testFilterFor($algorithm, $data, $expected)
    {
        $stream     = fopen("php://memory", "w+b");
        stream_filter_append($stream, 'cryptal.hash', STREAM_FILTER_READ, array('algorithm' => $algorithm));
        fwrite($stream, $data);
        fseek($stream, 0, SEEK_SET);
        $this->assertSame($expected, bin2hex(stream_get_contents($stream)));
    }
}
