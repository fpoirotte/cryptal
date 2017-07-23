<?php

namespace fpoirotte\Cryptal\DefaultAlgorithms;

use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\Implementers\MacInterface;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\Registry;

/**
 * Cipher-based message authentication code.
 *
 */
class Cmac extends MacInterface
{
    /**
     * See http://sci.crypt.narkive.com/3lS5EbY4/
     * and http://www.hpl.hp.com/techreports/98/HPL-98-135.pdf
     */
    protected static $polynomials = array(
        48  => "\x00\x2D",
        64  => "\x00\x1B",
        96  => "\x06\x41",
        128 => "\x00\x87",
        160 => "\x00\x2D",
        192 => "\x00\x87",
        224 => "\x03\x09",
        256 => "\x04\x25",
        384 => "\x10\x0D",
        512 => "\x01\x25",
    );

    private $data;
    private $k1;
    private $k2;
    private $cipher;

    public function __construct(MacEnum $macAlgorithm, SubAlgorithmAbstractEnum $innerAlgorithm, $key, $nonce = '')
    {
        if (MacEnum::MAC_CMAC() != $macAlgorithm) {
            throw new \InvalidArgumentException('Unsupported algorithm');
        }

        if (!($innerAlgorithm instanceof CipherEnum)) {
            throw new \InvalidArgumentException('A cipher was expected for the inner algorithm');
        }


        $cipher     = Registry::buildCipher($innerAlgorithm, ModeEnum::MODE_ECB(), new None, $key, 0, true);
        $blkSize    = $cipher->getBlockSize();
        if (!isset(self::$polynomials[$blkSize << 3])) {
            throw new \InvalidArgumentException('Unsupported cipher');
        }

        $null       = str_repeat("\x00", $blkSize);
        $polynomial = str_pad(self::$polynomials[$blkSize << 3], $blkSize, "\x00", STR_PAD_LEFT);
        $k0         = $cipher->encrypt('', $null);

        if ((ord($k0[0]) & 0x80) === 0) {
            $k1 = self::mul2mod($k0, $blkSize);
        } else {
            $k1 = self::mul2mod($k0, $blkSize) ^ $polynomial;
        }

        if ((ord($k1[0]) & 0x80) === 0) {
            $k2 = self::mul2mod($k1, $blkSize);
        } else {
            $k2 = self::mul2mod($k1, $blkSize) ^ $polynomial;
        }

        $this->data     = '';
        $this->k1       = $k1;
        $this->k2       = $k2;
        $this->cipher   = $cipher;
    }

    private static function mul2mod($n, $l)
    {
        $c = 0;
        for ($i = $l - 1; $i >= 0; $i--) {
            $t = (ord($n[$i]) << 1) + $c;
            $c = $t >> 8;
            $n[$i] = chr($t);
        }
        return $n;
    }

    protected function internalUpdate($data)
    {
        $this->data .= $data;
    }

    protected function internalFinish()
    {
        $blkSize    = $this->cipher->getBlockSize();
        $m          = str_split($this->data, $blkSize);
        $last       = count($m) - 1;
        $mk1        = $m[$last] ^ $this->k1;
        $mk2        = $this->k2 ^ str_pad($m[$last] . "\x80", $blkSize, "\x00", STR_PAD_RIGHT);

        if (strlen($m[$last]) === $blkSize) {
            $m[$last] = $mk1;
        } else {
            $m[$last] = $mk2;
        }

        $c = str_repeat("\x00", $blkSize);
        for ($i = 0, $max = count($m); $i < $max; $i++) {
            $c = $this->cipher->encrypt('', $c ^ $m[$i]);
        }
        return $c;
    }
}
