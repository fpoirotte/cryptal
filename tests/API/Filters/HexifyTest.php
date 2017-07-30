<?php

namespace fpoirotte\Cryptal\Tests\API\Filters;

use PHPUnit\Framework\TestCase;

class HexifyTest extends TestCase
{
    public function setUp()
    {
        // Initialize the library.
        \fpoirotte\Cryptal::init();
    }

    public function testFilter()
    {
        $input      = "hello world!\n";
        $expected   = bin2hex($input);
        $stream     = fopen("php://memory", "w+b");
        stream_filter_append($stream, 'cryptal.hexify', STREAM_FILTER_READ);
        fwrite($stream, $input);
        fseek($stream, 0, SEEK_SET);
        $this->assertSame($expected, stream_get_contents($stream));
    }
}
