<?php

use PHPUnit\Framework\TestCase;

class CryptoStreamTest extends TestCase
{
    protected $ctx;

    public function setUp()
    {
        // Initialize the library.
        \fpoirotte\Cryptal\init();
        $this->ctx = stream_context_create(
            array(
                'cryptal' => array(
                    'key'       => '0123456789abcdef',
                    'IV'        => '0123456789abcdef',
                    'padding'   => new \fpoirotte\Cryptal\Padding\Pkcs7,
                )
            )
        );
    }

    public function provider()
    {
        return array(
            'aes-128-cbc' => array('cbc', 'aes_128', null),
            'aes-128-cfb' => array('cfb', 'aes_128', null),
            'aes-128-ctr' => array('ctr', 'aes_128', null),
            'aes-128-ecb' => array('ecb', 'aes_128', null),
            'aes-128-ofb' => array('ofb', 'aes_128', null),
        );
    }

    /**
     * @dataProvider provider
     */
    public function testStream($mode, $cipher, $expected)
    {
        $plaintext = str_repeat("a", 16);
        $encrypt = fopen("cryptal.encrypt://$mode/$cipher", 'w+', false, $this->ctx);
        fwrite($encrypt, $plaintext);
        fflush($encrypt);
        $ciphertext = '';
        while ($data = fread($encrypt, 1024)) {
            $ciphertext .= $data;
        }
        //$this->assertSame($expected, bin2hex($ciphertext));

        $decrypt = fopen("cryptal.decrypt://$mode/$cipher", 'w+', false, $this->ctx);
        fwrite($decrypt, $ciphertext);
        fflush($decrypt);
        $plaintext2 = '';
        while ($data = fread($decrypt, 1024)) {
            $plaintext2 .= $data;
        }
        $this->assertSame(bin2hex($plaintext), bin2hex($plaintext2));
    }
}
