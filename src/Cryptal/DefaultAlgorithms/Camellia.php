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
 * Camellia cipher (RFC 3713).
 *
 * \see
 *      https://tools.ietf.org/html/rfc3713
 */
class Camellia implements CryptoInterface
{
    /// Original key length in bits (128, 192 or 256)
    protected $keyLength;

    protected $cipher;
    protected $key;

    /// Subkeys used for encryption
    protected $k;

    /// Subkeys used by the Feistel structure during encryption
    protected $ke;

    /// Subkeys used for whitening during encryption
    protected $kw;

    /// Subkeys used for decryption
    protected $k2;

    /// Subkeys used by the Feistel structure during decryption
    protected $ke2;

    /// Subkeys used for whitening during decryption
    protected $kw2;

    /// Sigma1 constant (from the RFC)
    const SIGMA1 = "\xA0\x9E\x66\x7F\x3B\xCC\x90\x8B";

    /// Sigma2 constant (from the RFC)
    const SIGMA2 = "\xB6\x7A\xE8\x58\x4C\xAA\x73\xB2";

    /// Sigma3 constant (from the RFC)
    const SIGMA3 = "\xC6\xEF\x37\x2F\xE9\x4F\x82\xBE";

    /// Sigma4 constant (from the RFC)
    const SIGMA4 = "\x54\xFF\x53\xA5\xF1\xD3\x6F\x1C";

    /// Sigma5 constant (from the RFC)
    const SIGMA5 = "\x10\xE5\x27\xFA\xDE\x68\x2D\x1D";

    /// Sigma6 constant (from the RFC)
    const SIGMA6 = "\xB0\x56\x88\xC2\xB3\xE6\xC1\xFD";

    /// Character string containing the whole sbox1 crypto-box
    protected static $sbox1 = null;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        if (null === self::$sbox1) {
            // Build and cache sbox1
            self::$sbox1 =
                "\x70\x82\x2C\xEC\xB3\x27\xC0\xE5\xE4\x85\x57\x35\xEA\x0C\xAE\x41" .
                "\x23\xEF\x6B\x93\x45\x19\xA5\x21\xED\x0E\x4F\x4E\x1D\x65\x92\xBD" .
                "\x86\xB8\xAF\x8F\x7C\xEB\x1F\xCE\x3E\x30\xDC\x5F\x5E\xC5\x0B\x1A" .
                "\xA6\xE1\x39\xCA\xD5\x47\x5D\x3D\xD9\x01\x5A\xD6\x51\x56\x6C\x4D" .
                "\x8B\x0D\x9A\x66\xFB\xCC\xB0\x2D\x74\x12\x2B\x20\xF0\xB1\x84\x99" .
                "\xDF\x4C\xCB\xC2\x34\x7E\x76\x05\x6D\xB7\xA9\x31\xD1\x17\x04\xD7" .
                "\x14\x58\x3A\x61\xDE\x1B\x11\x1C\x32\x0F\x9C\x16\x53\x18\xF2\x22" .
                "\xFE\x44\xCF\xB2\xC3\xB5\x7A\x91\x24\x08\xE8\xA8\x60\xFC\x69\x50" .
                "\xAA\xD0\xA0\x7D\xA1\x89\x62\x97\x54\x5B\x1E\x95\xE0\xFF\x64\xD2" .
                "\x10\xC4\x00\x48\xA3\xF7\x75\xDB\x8A\x03\xE6\xDA\x09\x3F\xDD\x94" .
                "\x87\x5C\x83\x02\xCD\x4A\x90\x33\x73\x67\xF6\xF3\x9D\x7F\xBF\xE2" .
                "\x52\x9B\xD8\x26\xC8\x37\xC6\x3B\x81\x96\x6F\x4B\x13\xBE\x63\x2E" .
                "\xE9\x79\xA7\x8C\x9F\x6E\xBC\x8E\x29\xF5\xF9\xB6\x2F\xFD\xB4\x59" .
                "\x78\x98\x06\x6A\xE7\x46\x71\xBA\xD4\x25\xAB\x42\x88\xA2\x8D\xFA" .
                "\x72\x07\xB9\x55\xF8\xEE\xAC\x0A\x36\x49\x2A\x68\x3C\x38\xF1\xA4" .
                "\x40\x28\xD3\x7B\xBB\xC9\x43\xC1\x15\xE3\xAD\xF4\x77\xC7\x80\x9E";
        }

        $supported = array(
            CipherEnum::CIPHER_CAMELIA_128(),
            CipherEnum::CIPHER_CAMELIA_192(),
            CipherEnum::CIPHER_CAMELIA_256(),
        );

        if (!in_array($cipher, $supported)) {
            throw new \InvalidArgumentException('Unsupported cipher');
        }

        if (ModeEnum::MODE_ECB() != $mode) {
            throw new \InvalidArgumentException('Unsupported mode');
        }

        $this->scheduleKeys($key);
        $this->key          = $key;
        $this->cipher       = $cipher;
    }

    /**
     * Perform a left rotation operation.
     *
     * \param string $value
     *      Big-endian string whose bits will be left-rotated
     *
     * \param int $n
     *      Number of bits to rotate to the left
     *
     * \retval string
     *      The result from rotating $n bits from $value
     */
    protected static function rotateLeft($value, $n)
    {
        $codes  = array_map('ord', str_split($value));
        $binary = vsprintf(str_repeat("%08b", strlen($value)), $codes);
        $rot    = substr($binary, $n) . substr($binary, 0, $n);
        $codes  = array_map('bindec', str_split($rot, 8));
        return implode('', array_map('chr', $codes));
    }

    /**
     * Perform key scheduling.
     *
     * \param string $key
     *      The key to schedule.
     *
     * \return
     *      This method does not return any value.
     *      Instead, several intermediate values are stored
     *      into the instance so that encryption/decryption
     *      operations may then take place.
     */
    protected function scheduleKeys($key)
    {
        // Compute KL & KR
        $KL                 = substr($key, 0, 16);
        $this->keyLength    = strlen($key) << 3;
        switch ($this->keyLength) {
            case 128:
                $KR     = str_repeat("\x00", 16);
                break;
            case 192:
                $KR     = substr($key, -8) . (substr($key, -8) ^ "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
                break;
            case 256:
                $KR     = substr($key, -16);
                break;
            default:
                throw new \InvalidArgumentException('Invalid key length');
        }

        // Compute KA & KB from KL & KR
        $D1 = substr($KL ^ $KR, 0, 8);
        $D2 = substr($KL ^ $KR, 8);
        $D2 ^= self::f($D1, self::SIGMA1);
        $D1 ^= self::f($D2, self::SIGMA2);
        $D1 ^= substr($KL, 0, 8);
        $D2 ^= substr($KL, 8);
        $D2 ^= self::f($D1, self::SIGMA3);
        $D1 ^= self::f($D2, self::SIGMA4);
        $KA = $D1 . $D2;
        $D1 = substr($KA ^ $KR, 0, 8);
        $D2 = substr($KA ^ $KR, 8);
        $D2 ^= self::f($D1, self::SIGMA5);
        $D1 ^= self::f($D2, self::SIGMA6);
        $KB = $D1 . $D2;
        unset($D1, $D2);

        // Alias KB & KR when the key is only 128-bit long
        if (128 === $this->keyLength) {
            $KB = $KA;
            $KR = $KL;
        }

        // Compute kw1..kw2, k1..k6
        $kw = $k = $ke = array(null);
        $kw[] = substr(self::rotateLeft($KL, 0), 0, 8);         // kw1
        $kw[] = substr(self::rotateLeft($KL, 0), 8);            // kw2
        $k[]  = substr(self::rotateLeft($KB, 0), 0, 8);         // k1
        $k[]  = substr(self::rotateLeft($KB, 0), 8);            // k2
        $k[]  = substr(self::rotateLeft($KR, 15), 0, 8);        // k3
        $k[]  = substr(self::rotateLeft($KR, 15), 8);           // k4
        $k[]  = substr(self::rotateLeft($KA, 15), 0, 8);        // k5
        $k[]  = substr(self::rotateLeft($KA, 15), 8);           // k6

        if (128 === $this->keyLength) {
            $ke[] = substr(self::rotateLeft($KA, 30), 0, 8);    // ke1
            $ke[] = substr(self::rotateLeft($KA, 30), 8);       // ke2
        } else {
            $ke[] = substr(self::rotateLeft($KR, 30), 0, 8);    // ke1
            $ke[] = substr(self::rotateLeft($KR, 30), 8);       // ke2
            $k[]  = substr(self::rotateLeft($KB, 30), 0, 8);    // k7
            $k[]  = substr(self::rotateLeft($KB, 30), 8);       // k8
        }

        // k7..k9 or k9..k11, depending on key size
        $k[]  = substr(self::rotateLeft($KL, 45), 0, 8);
        $k[]  = substr(self::rotateLeft($KL, 45), 8);
        $k[]  = substr(self::rotateLeft($KA, 45), 0, 8);

        if (128 === $this->keyLength) {
            $k[]  = substr(self::rotateLeft($KL, 60), 8);       // k10
        } else {
            $k[]  = substr(self::rotateLeft($KA, 45), 8);       // k12
            $ke[] = substr(self::rotateLeft($KL, 60), 0, 8);    // ke3
            $ke[] = substr(self::rotateLeft($KL, 60), 8);       // ke4
            $k[]  = substr(self::rotateLeft($KR, 60), 0, 8);    // k13
            $k[]  = substr(self::rotateLeft($KR, 60), 8);       // k14
        }

        // k11..k12 or k15..k16, depending on key size
        $k[]  = substr(self::rotateLeft($KB, 60), 0, 8);
        $k[]  = substr(self::rotateLeft($KB, 60), 8);

        if (128 === $this->keyLength) {
            $ke[] = substr(self::rotateLeft($KL, 77), 0, 8);    // ke3
            $ke[] = substr(self::rotateLeft($KL, 77), 8);       // ke4
        } else {
            $k[]  = substr(self::rotateLeft($KL, 77), 0, 8);    // k17
            $k[]  = substr(self::rotateLeft($KL, 77), 8);       // k18
            $ke[] = substr(self::rotateLeft($KA, 77), 0, 8);    // ke5
            $ke[] = substr(self::rotateLeft($KA, 77), 8);       // ke6
        }

        // k13..k18 or k19..k24, and kw3..kw4
        $k[]  = substr(self::rotateLeft($KR, 94), 0, 8);
        $k[]  = substr(self::rotateLeft($KR, 94), 8);
        $k[]  = substr(self::rotateLeft($KA, 94), 0, 8);
        $k[]  = substr(self::rotateLeft($KA, 94), 8);
        $k[]  = substr(self::rotateLeft($KL, 111), 0, 8);
        $k[]  = substr(self::rotateLeft($KL, 111), 8);
        $kw[] = substr(self::rotateLeft($KB, 111), 0, 8);
        $kw[] = substr(self::rotateLeft($KB, 111), 8);

        unset($k[0], $ke[0], $kw[0]);
        $this->k    = $k;
        $this->ke   = $ke;
        $this->kw   = $kw;

        // Build the reverse map for keys
        $k2 = $ke2 = $kw2 = array();
        for ($i = 1, $n = count($k); $i <= $n; $i++) {
            $k2[$i] = $k[$n - $i + 1];
        }
        for ($i = 1, $n = count($ke); $i <= $n; $i++) {
            $ke2[$i] = $ke[$n - $i + 1];
        }
        $kw2[1] = $kw[3];
        $kw2[2] = $kw[4];
        $kw2[3] = $kw[1];
        $kw2[4] = $kw[2];
        $this->k2   = $k2;
        $this->ke2  = $ke2;
        $this->kw2  = $kw2;
    }

    /**
     * Retrieve the sbox value at a given index.
     *
     * \param int $n
     *      A number between 1 and 4 indicating the sbox
     *      from which the resulting value will be taken.
     *
     * \param string
     *      A single character indicating the index
     *      in the sbox whose value should be returned.
     *
     * \retval string
     *      A single character: the value for the given
     *      sbox and index.
     */
    protected static function sbox($n, $x)
    {
        // We try to make this method resilient against timing attacks.
        if (4 === $n) {
            $x = self::rotateLeft($x, 1);
        } else {
            $x = self::rotateLeft($x, 0);
        }

        $rotation   = array(1 => 0, 1, 7, 0);
        return self::rotateLeft(self::$sbox1[ord($x)], $rotation[$n]);
    }

    /**
     * F-function (per RFC 3713)
     *
     * \param string $F_IN
     *      64-bit input data for the function
     *
     * \param string $KE
     *      64-bit subkey
     *
     * \retval string
     *      64-bit output data
     */
    protected function f($F_IN, $KE)
    {
        $x  = $F_IN ^ $KE;
        $t  = str_split($x);
        $t1 = self::sbox(1, $t[0]);
        $t2 = self::sbox(2, $t[1]);
        $t3 = self::sbox(3, $t[2]);
        $t4 = self::sbox(4, $t[3]);
        $t5 = self::sbox(2, $t[4]);
        $t6 = self::sbox(3, $t[5]);
        $t7 = self::sbox(4, $t[6]);
        $t8 = self::sbox(1, $t[7]);
        $y1 = $t1 ^ $t3 ^ $t4 ^ $t6 ^ $t7 ^ $t8;
        $y2 = $t1 ^ $t2 ^ $t4 ^ $t5 ^ $t7 ^ $t8;
        $y3 = $t1 ^ $t2 ^ $t3 ^ $t5 ^ $t6 ^ $t8;
        $y4 = $t2 ^ $t3 ^ $t4 ^ $t5 ^ $t6 ^ $t7;
        $y5 = $t1 ^ $t2 ^ $t6 ^ $t7 ^ $t8;
        $y6 = $t2 ^ $t3 ^ $t5 ^ $t7 ^ $t8;
        $y7 = $t3 ^ $t4 ^ $t5 ^ $t6 ^ $t8;
        $y8 = $t1 ^ $t4 ^ $t5 ^ $t6 ^ $t7;
        $res = $y1 . $y2 . $y3 . $y4 . $y5 . $y6 . $y7 . $y8;
        return $res;
    }

    /**
     * Feistel function (per RFC 3713)
     *
     * \param string $FL_IN
     *      64-bit input data for the function
     *
     * \param string $KE
     *      64-bit subkey
     *
     * \retval string
     *      64-bit output data
     *
     * \note
     *      This method does the opposite of the flinv() method.
     */
    protected static function fl($FL_IN, $KE)
    {
        $x1 = substr($FL_IN, 0, 4);
        $x2 = substr($FL_IN, 4);
        $k1 = substr($KE, 0, 4);
        $k2 = substr($KE, 4);
        $x2 ^= self::rotateLeft($x1 & $k1, 1);
        $x1 ^= ($x2 | $k2);
        $res = $x1 . $x2;
        return $res;
    }

    /**
     * Inverse Feistel function (per RFC 3713)
     *
     * \param string $FLINV_IN
     *      64-bit input data for the function
     *
     * \param string $KE
     *      64-bit subkey
     *
     * \retval string
     *      64-bit output data
     *
     * \note
     *      This method does the opposite of the fl() method.
     */
    protected static function flinv($FLINV_IN, $KE)
    {
        $y1 = substr($FLINV_IN, 0, 4);
        $y2 = substr($FLINV_IN, 4);
        $k1 = substr($KE, 0, 4);
        $k2 = substr($KE, 4);
        $y1 ^= ($y2 | $k2);
        $y2 ^= self::rotateLeft($y1 & $k1, 1);
        $res = $y1 . $y2;
        return $res;
    }

    /**
     * Internal encryption/decryption routine.
     *
     * \param string $m
     *      A block of data to encrypt or decrypt.
     *
     * \param array $k
     *      Subkeys used for the operation
     *
     * \param array $ke
     *      Subkeys used by the Feistel structure
     *
     * \param array $kw
     *      Subkeys used for whitening
     *
     * \retval string
     *      Encrypted/decrypted block
     *
     * \note
     *      Whether this method is actually encrypting/decrypting data
     *      is determined purely by the values of $k, $ke and $kw.
     */
    protected function xcrypt($m, array $k, array $ke, array $kw)
    {
        $D1 = substr($m, 0, 8);
        $D2 = substr($m, 8);

        // Pre-whitening
        $D1 ^= $kw[1];
        $D2 ^= $kw[2];

        $nbBlocks = count($k) / 6;
        for ($i = 0; $i < $nbBlocks; $i++) {
            if ($i > 0) {
                $D1 = self::fl($D1, $ke[$i * 2 - 1]);
                $D2 = self::flinv($D2, $ke[$i * 2]);
            }

            $D2 ^= self::f($D1, $k[$i * 6 + 1]);
            $D1 ^= self::f($D2, $k[$i * 6 + 2]);
            $D2 ^= self::f($D1, $k[$i * 6 + 3]);
            $D1 ^= self::f($D2, $k[$i * 6 + 4]);
            $D2 ^= self::f($D1, $k[$i * 6 + 5]);
            $D1 ^= self::f($D2, $k[$i * 6 + 6]);
        }

        // Post-whitening
        $D2 ^= $kw[3];
        $D1 ^= $kw[4];

        return $D2 . $D1;
    }

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        $blockSize = $this->getBlockSize();
        if (strlen($data) % $blockSize) {
            throw new \InvalidArgumentException('Invalid block');
        }

        $res = '';
        foreach (str_split($data, $blockSize) as $block) {
            $res .= $this->xcrypt($block, $this->k, $this->ke, $this->kw);
        }
        return $res;
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {
        $blockSize = $this->getBlockSize();
        if (strlen($data) % $blockSize) {
            throw new \InvalidArgumentException('Invalid block');
        }

        $res = '';
        foreach (str_split($data, $blockSize) as $block) {
            $res .= $this->xcrypt($block, $this->k2, $this->ke2, $this->kw2);
        }
        return $res;
    }

    public function getIVSize()
    {
        return 16;
    }

    public function getBlockSize()
    {
        return 16;
    }

    public function getCipher()
    {
        return $this->cipher;
    }

    public function getKey()
    {
        return $this->key;
    }
}
