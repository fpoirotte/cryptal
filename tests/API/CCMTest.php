<?php

namespace fpoirotte\Cryptal\Tests\API;

class CCMTest extends AesBasedTestCase
{
    public function vectors()
    {
        // K, N, A, P, C, T
        return array(
            // Test vectors from RFC 3610
            array(
                'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF',
                '00000003020100A0A1A2A3A4A5',
                '0001020304050607',
                '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E',
                '588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384',
                '17E8D12CFDF926E0',
            ),
            array(
                'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF',
                '00000004030201A0A1A2A3A4A5',
                '0001020304050607',
                '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
                '72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3B',
                'A091D56E10400916',
            ),
            array(
                'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF',
                '00000005040302A0A1A2A3A4A5',
                '0001020304050607',
                '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20',
                '51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA859657',
                '4ADAA76FBD9FB0C5',
            ),
            array(
                'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF',
                '00000006050403A0A1A2A3A4A5',
                '000102030405060708090A0B',
                '0C0D0E0F101112131415161718191A1B1C1D1E',
                'A28C6865939A9A79FAAA5C4C2A9D4A91CDAC8C',
                '96C861B9C9E61EF1',
            ),
            array(
                'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF',
                '00000007060504A0A1A2A3A4A5',
                '000102030405060708090A0B',
                '0C0D0E0F101112131415161718191A1B1C1D1E1F',
                'DCF1FB7B5D9E23FB9D4E131253658AD86EBDCA3E',
                '51E83F077D9C2D93',
            ),
            array(
                'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF',
                '00000008070605A0A1A2A3A4A5',
                '000102030405060708090A0B',
                '0C0D0E0F101112131415161718191A1B1C1D1E1F20',
                '6FC1B011F006568B5171A42D953D469B2570A4BD87',
                '405A0443AC91CB94',
            ),
            array(
                'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF',
                '00000009080706A0A1A2A3A4A5',
                '0001020304050607',
                '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E',
                '0135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C',
                '048C56602C97ACBB7490',
            ),
        );
    }

    /**
     * @dataProvider vectors
     */
    public function testCCM_Mode($K, $N, $A, $P, $C, $T)
    {
        $K  = pack('H*', $K);
        $P  = pack('H*', $P);
        $A  = pack('H*', $A);
        $N  = pack('H*', $N);
        $C  = strtolower($C);
        $T  = strtolower($T);

        $cipher     = $this->getCipher($K);
        $ccm        = new \fpoirotte\Cryptal\Modes\CCM($cipher, $N, strlen($T) >> 1);
        $ctx        = stream_context_create(array('cryptal' => array('data'  => $A)));

        $res        = $ccm->encrypt($P, $ctx);
        $options    = stream_context_get_options($ctx);
        $this->assertSame($C, bin2hex($res));
        $this->assertSame($T, bin2hex($options['cryptal']['tag']));

        $res        = $ccm->decrypt($res, $ctx);
        $this->assertSame(bin2hex($P), bin2hex($res));
    }
}
