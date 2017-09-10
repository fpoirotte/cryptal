<?php

namespace fpoirotte\Cryptal\Tests\API\Filters;

use PHPUnit\Framework\TestCase;

class BinifyTest extends TestCase
{
    public function testValidData()
    {
        $expected   = "hello world!\n";
        $input      = bin2hex($expected);
        $stream     = tmpfile();
        stream_filter_append($stream, 'cryptal.binify', STREAM_FILTER_READ);
        fwrite($stream, $input);
        fseek($stream, 0, SEEK_SET);
        $this->assertSame($expected, stream_get_contents($stream));
    }

    /**
     * @expectedException           RuntimeException
     * @expectedExceptionMessage    Invalid data in input
     */
    public function testInvalidByte()
    {
        $input      = "ZZ";
        $stream     = tmpfile();
        stream_filter_append($stream, 'cryptal.binify', STREAM_FILTER_READ);
        fwrite($stream, $input);
        fseek($stream, 0, SEEK_SET);
        $this->assertSame('foo', stream_get_contents($stream));
    }

    /**
     * @expectedException           RuntimeException
     * @expectedExceptionMessage    Odd number of bytes in input
     */
    public function testOddNumberOfBytes()
    {
        $input      = "303";
        $stream     = tmpfile();
        stream_filter_append($stream, 'cryptal.binify', STREAM_FILTER_READ);
        fwrite($stream, $input);
        fseek($stream, 0, SEEK_SET);
        $this->assertSame('0', stream_get_contents($stream));
    }
}
