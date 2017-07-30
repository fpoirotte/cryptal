<?php

namespace fpoirotte\Cryptal\Tests\API\Filters;

use PHPUnit\Framework\TestCase;

class HexifyTest extends TestCase
{
    public function testLowercaseOutput()
    {
        $input      = "hello world!\n";
        $expected   = bin2hex($input);
        $stream     = fopen("php://memory", "w+b");
        stream_filter_append($stream, 'cryptal.hexify', STREAM_FILTER_READ);
        fwrite($stream, $input);
        fseek($stream, 0, SEEK_SET);
        $this->assertSame($expected, stream_get_contents($stream));
    }

    public function testUppercaseOutput()
    {
        $input      = "hello world!\n";
        $expected   = strtoupper(bin2hex($input));
        $stream     = fopen("php://memory", "w+b");
        stream_filter_append($stream, 'cryptal.hexify', STREAM_FILTER_READ, array('uppercase' => true));
        fwrite($stream, $input);
        fseek($stream, 0, SEEK_SET);
        $this->assertSame($expected, stream_get_contents($stream));
    }
}
