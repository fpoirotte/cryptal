<?php

namespace fpoirotte\Cryptal\Modes;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\AsymmetricModeInterface;

/**
 * Offset Codebook (OCB) mode
 *
 * \note
 *      Even though OCB was carefully designed to work with arbitrary
 *      bitstrings, this implementation only supports bytestrings,
 *      that is, strings whose length is a multiple of 8 bits.
 */
class OCB implements AsymmetricModeInterface
{
    /// Approved block cipher with a 128-bit block size
    protected $cipher;

    /// Secret key
    protected $key;

    /// Initialization Vector
    protected $iv;

    /// Output tag length (in bytes)
    protected $taglen;

    public function __construct(CryptoInterface $cipher, $iv, $tagLength)
    {
        if (16 !== $cipher->getBlockSize()) {
            throw new \InvalidArgumentException('Incompatible cipher (block size != 16)');
        }

        if ($tagLength > 16) {
            throw new \InvalidArgumentException('Invalid tag length (must be in 0..16)');
        }

        if (strlen($iv) > 15) {
            throw new \InvalidArgumentException('Invalid nonce length (must be in 0..16)');
        }

        $this->taglen   = $tagLength;
        $this->cipher   = $cipher;
        $this->iv       = $iv;
        $this->l        = new \fpoirotte\Cryptal\Modes\OCB\Lseries($cipher);
    }

    protected static function ntz($n)
    {
        return strcspn(strrev(decbin($n)), '1');
    }

    protected function hash($A)
    {
        $m      = strlen($A) >> 4;  // number of 128-bit blocks in A
        $Atail  = strlen($A) % 16;  // 0 if the last block is a full block
        $A      = str_split($A, 16);

        $Sum = $Offset = str_repeat("\x00", 16);
        for ($i = 0; $i < $m; $i++) {
            $Offset ^= $this->l[self::ntz($i + 1)];
            $Sum    ^= $this->cipher->encrypt('', $A[$i] ^ $Offset);
        }

        if ($Atail) {
            $Offset     ^= $this->l['*'];
            $CipherInput = str_pad($A[$m] . "\x80", 16, "\x00") ^ $Offset;
            $Sum        ^= $this->cipher->encrypt('', $CipherInput);
        }

        return $Sum;
    }

    public function encrypt($data, $context)
    {
        $options    = stream_context_get_options($context);
        $A          = isset($options['cryptal']['data']) ? (string) $options['cryptal']['data'] : '';

        $m          = strlen($data) >> 4;   // number of 128-bit blocks in P
        $Ptail      = strlen($data) % 16;   // 0 if the last block is a full block
        $P          = str_split($data, 16);

        $Nlen       = strlen($this->iv);
        $Nonce      = sprintf("%07b", ($this->taglen << 3) % 128) . str_repeat('0', 120 - ($Nlen << 3)) . '1' .
                      vsprintf(str_repeat("%08b", $Nlen), array_map('ord', str_split($this->iv)));
        $bottom     = bindec(substr($Nonce, 122));
        $Ktop       = array_map('bindec', str_split(substr($Nonce, 0, 122) . '000000', 8));
        $Ktop       = $this->cipher->encrypt('', implode('', array_map('chr', $Ktop)));
        $Stretch    = $Ktop . (substr($Ktop, 0, 8) ^ substr($Ktop, 1, 8));
        $Offset     = vsprintf(str_repeat("%08b", 24), array_map('ord', str_split($Stretch)));
        $Offset     = substr($Offset, $bottom, 128);
        $Offset     = array_map('bindec', str_split($Offset, 8));
        $Offset     = implode('', array_map('chr', $Offset));
        $Checksum   = str_repeat("\x00", 16);

        $C = '';
        for ($i = 0; $i < $m; $i++) {
            $Offset    ^= $this->l[self::ntz($i + 1)];
            $C         .= $Offset ^ $this->cipher->encrypt('', $P[$i] ^ $Offset);
            $Checksum  ^= $P[$i];
        }

        if ($Ptail) {
            $Offset    ^= $this->l['*'];
            $Pad        = $this->cipher->encrypt('', $Offset);
            $C         .= $P[$m] ^ $Pad;
            $Checksum  ^= str_pad($P[$m] . "\x80", 16, "\x00");
        }

        $Tag    = $this->cipher->encrypt('', $Checksum ^ $Offset ^ $this->l['$']) ^ $this->hash($A);
        stream_context_set_option($context, 'cryptal', 'tag', substr($Tag, 0, $this->taglen));
        return $C;
    }

    public function decrypt($data, $context)
    {
        $options = stream_context_get_options($context);
        $A = isset($options['cryptal']['data']) ? (string) $options['cryptal']['data'] : '';
        $T = isset($options['cryptal']['tag']) ? (string) $options['cryptal']['tag'] : '';

        $m          = strlen($data) >> 4;   // number of 128-bit blocks in C
        $Ctail      = strlen($data) % 16;   // 0 if the last block is a full block
        $C          = str_split($data, 16);

        $Nlen       = strlen($this->iv);
        $Nonce      = sprintf("%07b", ($this->taglen << 3) % 128) . str_repeat('0', 120 - ($Nlen << 3)) . '1' .
                      vsprintf(str_repeat("%08b", $Nlen), array_map('ord', str_split($this->iv)));
        $bottom     = bindec(substr($Nonce, 122));
        $Ktop       = array_map('bindec', str_split(substr($Nonce, 0, 122) . '000000', 8));
        $Ktop       = $this->cipher->encrypt('', implode('', array_map('chr', $Ktop)));
        $Stretch    = $Ktop . (substr($Ktop, 0, 8) ^ substr($Ktop, 1, 8));
        $Offset     = vsprintf(str_repeat("%08b", 24), array_map('ord', str_split($Stretch)));
        $Offset     = substr($Offset, $bottom, 128);
        $Offset     = array_map('bindec', str_split($Offset, 8));
        $Offset     = implode('', array_map('chr', $Offset));
        $Checksum   = str_repeat("\x00", 16);

        $P = '';
        for ($i = 0; $i < $m; $i++) {
            $Offset    ^= $this->l[self::ntz($i + 1)];
            $decoded    = $Offset ^ $this->cipher->decrypt('', $C[$i] ^ $Offset);
            $P         .= $decoded;
            $Checksum  ^= $decoded;
        }

        if ($Ctail) {
            $Offset    ^= $this->l['*'];
            $Pad        = $this->cipher->encrypt('', $Offset);
            $Pstar      = $C[$m] ^ $Pad;
            $P         .= $Pstar;
            $Checksum  ^= str_pad($Pstar . "\x80", 16, "\x00");
        }

        $Tag    = $this->cipher->encrypt('', $Checksum ^ $Offset ^ $this->l['$']) ^ $this->hash($A);
        if ((string) substr($Tag, 0, $this->taglen) !== $T) {
            throw new \InvalidArgumentException('Tag does not match expected value');
        }

        return $P;
    }
}
