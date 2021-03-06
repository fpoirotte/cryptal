<?php

namespace fpoirotte\Cryptal\Tests\API\Modes;

use fpoirotte\Cryptal\Tests\AesBasedTestCase;

class OCMTest extends AesBasedTestCase
{
    public function vectors()
    {
        // K, N, A, P, C, T
        return array(
            // Test vectors from RFC 7253
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221100',
                '',
                '',
                '',
                '785407BFFFC8AD9EDCC5520AC9111EE6',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221101',
                '0001020304050607',
                '0001020304050607',
                '6820B3657B6F615A',
                '5725BDA0D3B4EB3A257C9AF1F8F03009',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221102',
                '0001020304050607',
                '',
                '',
                '81017F8203F081277152FADE694A0A00',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221103',
                '',
                '0001020304050607',
                '45DD69F8F5AAE724',
                '14054CD1F35D82760B2CD00D2F99BFA9',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221104',
                '000102030405060708090a0b0c0d0e0f',
                '000102030405060708090a0b0c0d0e0f',
                '571D535B60B277188BE5147170A9A22C',
                '3AD7A4FF3835B8C5701C1CCEC8FC3358',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221105',
                '000102030405060708090a0b0c0d0e0f',
                '',
                '',
                '8CF761B6902EF764462AD86498CA6B97',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221106',
                '',
                '000102030405060708090a0b0c0d0e0f',
                '5CE88EC2E0692706A915C00AEB8B2396',
                'F40E1C743F52436BDF06D8FA1ECA343D',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221107',
                '000102030405060708090a0b0c0d0e0f1011121314151617',
                '000102030405060708090a0b0c0d0e0f1011121314151617',
                '1CA2207308C87C010756104D8840CE1952F09673A448A122',
                'C92C62241051F57356D7F3C90BB0E07F',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221108',
                '000102030405060708090a0b0c0d0e0f1011121314151617',
                '',
                '',
                '6DC225A071FC1B9F7C69F93B0F1E10DE',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA99887766554433221109',
                '',
                '000102030405060708090a0b0c0d0e0f1011121314151617',
                '221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3C',
                'E725F32494B9F914D85C0B1EB38357FF',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA9988776655443322110A',
                '000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F',
                '000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F',
                'BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A485',
                '40FBBA186C5553C68AD9F592A79A4240',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA9988776655443322110B',
                '000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F',
                '',
                '',
                'FE80690BEE8A485D11F32965BC9D2A32',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA9988776655443322110C',
                '',
                '000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F',
                '2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDF',
                'B5E1DDE3BC18A5F840B52E653444D5DF',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA9988776655443322110D',
                '000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F2021222324252627',
                '000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F2021222324252627',
                'D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7A',
                'ED07BA06A4A69483A7035490C5769E60',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA9988776655443322110E',
                '000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F2021222324252627',
                '',
                '',
                'C5CD9D1850C141E358649994EE701B68',
            ),
            array(
                '000102030405060708090a0b0c0d0e0f',
                'BBAA9988776655443322110F',
                '',
                '000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F2021222324252627',
                '4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E',
                '479AD363AC366B95A98CA5F3000B1479',
            ),

            array(
                '0f0e0d0c0b0a09080706050403020100',
                'BBAA9988776655443322110D',
                '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
                '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
                '1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1A0124B0A55BAE884ED93481529C76B6A',
                'D0C515F4D1CDD4FDAC4F02AA',
            ),
        );
    }

    /**
     * @dataProvider vectors
     */
    public function testOCB_Mode($K, $N, $A, $P, $C, $T)
    {
        $K  = pack('H*', $K);
        $P  = pack('H*', $P);
        $A  = pack('H*', $A);
        $N  = pack('H*', $N);
        $C  = strtolower($C);
        $T  = strtolower($T);

        $cipher     = $this->getCipher($K);
        $ocb        = new \fpoirotte\Cryptal\Modes\OCB($cipher, $N, strlen($T) >> 1);
        $ctx        = stream_context_create(array('cryptal' => array('data'  => $A)));

        $res        = $ocb->encrypt($P, $ctx);
        $options    = stream_context_get_options($ctx);
        $this->assertSame($C, bin2hex($res));
        $this->assertSame($T, bin2hex($options['cryptal']['tag']));

        $res        = $ocb->decrypt($res, $ctx);
        $this->assertSame(bin2hex($P), bin2hex($res));
    }
}
