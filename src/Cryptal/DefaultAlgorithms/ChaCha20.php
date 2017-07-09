<?php

namespace fpoirotte\Cryptal\DefaultAlgorithms;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\SubAlgorithmInterface;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\DefaultAlgorithms\Poly1305;

/**
 * ChaCha20 block cipher, with optional AEAD (as per RFC 7539).
 *
 * \note
 *      When using AEAD, this class implements the construction defined in RFC 7539.
 *
 * \see
 *      http://cr.yp.to/chacha/chacha-20080128.pdf
 * \see
 *      https://tools.ietf.org/html/rfc7539
 */
class ChaCha20 implements CryptoInterface
{
    /// Secret key used to encrypt/decrypt data.
    protected $key;

    /// Tag length in bytes; 16 when AEAD is enabled, 0 otherwise.
    protected $tagLength;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        if (CipherEnum::CIPHER_CHACHA20() !== $cipher) {
            throw new \InvalidArgumentException('Unsupported cipher');
        }

        if (!($padding instanceof None)) {
            throw new \InvalidArgumentException(
                'ChaCha20 does not need any padding ' .
                '(hint: use fpoirotte\Cryptal\Padding\None)'
            );
        }

        if (0 !== $tagLength && 16 !== $tagLength) {
            throw new \InvalidArgumentException('Invalid tag length: must be 16 to enable AEAD, 0 to disable');
        }

        if (32 !== strlen($key)) {
            throw new \InvalidArgumentException('Invalid key length');
        }

        $this->tagLength    = $tagLength;
        $this->key          = $key;
    }

    protected static function quarterRound(&$a, &$b, &$c, &$d)
    {
        $a += $b;
        $a &= 0xFFFFFFFF;
        $d ^= $a;
        $d = (($d & 0xFFFF) << 16) | (($d >> 16) & 0xFFFF);

        $c += $d;
        $c &= 0xFFFFFFFF;
        $b ^= $c;
        $b = (($b & 0xFFFFF) << 12) | (($b >> 20) & 0xFFF);

        $a += $b;
        $a &= 0xFFFFFFFF;
        $d ^= $a;
        $d = (($d & 0xFFFFFF) << 8) | (($d >> 24) & 0xFF);

        $c += $d;
        $c &= 0xFFFFFFFF;
        $b ^= $c;
        $b = (($b & 0x1FFFFFF) << 7) | (($b >> 25) & 0x7F);
    }

    protected function block($iv, $counter)
    {
        
        $block = array_values(
            unpack('V*', 'expand 32-byte k' . $this->key . $counter . $iv)
        );
        $init  = $block;

        for ($i = 0; $i < 10; $i++) {
            static::quarterRound($block[ 0], $block[ 4], $block[ 8], $block[12]);
            static::quarterRound($block[ 1], $block[ 5], $block[ 9], $block[13]);
            static::quarterRound($block[ 2], $block[ 6], $block[10], $block[14]);
            static::quarterRound($block[ 3], $block[ 7], $block[11], $block[15]);

            static::quarterRound($block[ 0], $block[ 5], $block[10], $block[15]);
            static::quarterRound($block[ 1], $block[ 6], $block[11], $block[12]);
            static::quarterRound($block[ 2], $block[ 7], $block[ 8], $block[13]);
            static::quarterRound($block[ 3], $block[ 4], $block[ 9], $block[14]);
        }

        $res = '';
        for ($i = 0; $i < 16; $i++) {
            $res .= pack('V', ($block[$i] + $init[$i]) & 0xFFFFFFFF);
        }
        return $res;
    }

    protected function basicXcrypt($plain, $iv, $counter = 0)
    {
        $ivSize = $this->getIVSize();
        if (strlen($iv) !== $ivSize) {
            throw new \InvalidArgumentException("Invalid Initialization Vector (should be $ivSize bytes long)");
        }

        $len = strlen($plain);
        $m = ($len >> 6) + (($len % 64) > 0);
        $keyStream = '';
        for ($i = 0; $i < $m; $i++) {
            $c = gmp_strval(gmp_add($counter, $i), 16);
            $c = pack('H*', str_pad($c, (16 - $ivSize) << 1, '0', STR_PAD_LEFT));
            $keyStream .= $this->block($iv, strrev($c));
        }
        return $plain ^ $keyStream;
    }

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        if (!$this->tagLength) {
            return $this->basicXcrypt($data, $iv, 0);
        }

        $polyKey    = substr($this->block($iv, str_repeat("\x00", 4)), 0, 32);
        $ciphertext = $this->basicXcrypt($data, $iv, 1);
        $pad1       = str_repeat("\x00", (16 - (strlen($aad) % 16)) % 16);
        $pad2       = str_repeat("\x00", (16 - (strlen($ciphertext) % 16)) % 16);
        $aadLen     = pack('V*', strlen($aad), 0);
        $ctLen      = pack('V*', strlen($ciphertext), 0);
        $tag        = Poly1305::mac(
            MacEnum::MAC_POLY1305(),
            CipherEnum::CIPHER_CHACHA20(),
            $polyKey,
            $aad . $pad1 . $ciphertext . $pad2 . $aadLen . $ctLen,
            '',
            true
        );
        return $ciphertext;
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {
        if (!$this->tagLength) {
            return $this->basicXcrypt($data, $iv, 0);
        }

        $polyKey    = substr($this->block($iv, str_repeat("\x00", 4)), 0, 32);
        $pad1       = str_repeat("\x00", (16 - (strlen($aad) % 16)) % 16);
        $pad2       = str_repeat("\x00", (16 - (strlen($data) % 16)) % 16);
        $aadLen     = pack('V*', strlen($aad), 0);
        $ctLen      = pack('V*', strlen($data), 0);
        $outTag     = Poly1305::mac(
            MacEnum::MAC_POLY1305(),
            CipherEnum::CIPHER_CHACHA20(),
            $polyKey,
            $aad . $pad1 . $data . $pad2 . $aadLen . $ctLen,
            '',
            true
        );

        if ($outTag !== $tag) {
            throw new \InvalidArgumentException('Invalid tag');
        }

        return $this->basicXcrypt($data, $iv, 1);
    }

    public function getIVSize()
    {
        return 12;
    }

    public function getBlockSize()
    {
        // ChaCha20 does not use blocks, which is the same
        // as saying each byte in the input is a separate block.
        return 1;
    }
}
