<?php

namespace fpoirotte\Cryptal\Tests\API\Filters;

use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\Tests\AesBasedTestCase;

class MacTest extends AesBasedTestCase
{
    public function testFilter()
    {
        // This test vector was verified against http://adder.demo.iworks.ro/Go/OMAC/
        $expected   = 'a9a5079a7e416683be1e24ddca8d22a2';
        $stream     = fopen("php://memory", "w+b");
        stream_filter_append(
            $stream,
            'cryptal.mac',
            STREAM_FILTER_READ,
            array(
                'algorithm'         => MacEnum::MAC_CMAC(),
                'innerAlgorithm'    => CipherEnum::CIPHER_AES_128(),
                'key'               => pack('H*', '0f0e0d0c0b0a09080706050403020100'),

                // Since both the CMAC implementation and the AES stub
                // are based on userland PHP code, this must be set to true.
                'allowUnsafe'       => true,
            )
        );
        fwrite($stream, "hello world!\n");
        fseek($stream, 0, SEEK_SET);
        $this->assertSame($expected, bin2hex(stream_get_contents($stream)));
    }
}
