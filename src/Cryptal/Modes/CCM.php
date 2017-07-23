<?php

namespace fpoirotte\Cryptal\Modes;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\AsymmetricModeInterface;

/**
 * Counter with CBC-MAC (CCM)
 */
class CCM implements AsymmetricModeInterface
{
    /// Cipher
    protected $cipher;

    /// Nonce
    protected $nonce;

    /// Length parameter
    protected $L;

    /// Output tag length
    protected $M;

    public function __construct(CryptoInterface $cipher, $iv, $tagLength)
    {
        if (16 !== $cipher->getBlockSize()) {
            throw new \InvalidArgumentException('Incompatible cipher (block size != 16)');
        }

        $nonceSize  = strlen($iv);
        if ($nonceSize < 7 || $nonceSize > 13) {
            throw new \Exception("Invalid nonce (should be between 7 and 13 bytes long)");
        }

        if (($tagLength & 0x1) || $tagLength < 4 || $tagLength > 16) {
            throw new \Exception("Invalid tag length (valid values: 4, 6, 8, 10, 12, 14 & 16)");
        }

        $this->cipher   = $cipher;
        $this->nonce    = $iv;
        $this->L        = 15 - $nonceSize;
        $this->M        = ($tagLength - 2) >> 1;
    }

    protected function checkum($M, $A)
    {
        $len = strlen($M);
        for ($i = 0; $i < $this->L; $i++) {
            $len >>= 8;
        }
        if ($len > 0) {
            throw new \InvalidArgumentException('Invalid length for input data (greater than 2**8L)');
        }

        // Build the first block.
        // Note: l(m) is < 2**32 in this implementation
        $lenA   = strlen($A);
        $lenM   = str_pad(ltrim(pack('N', strlen($M)), "\x00"), $this->L, "\x00", STR_PAD_LEFT);
        $b      = chr((($lenA > 0) << 6) | ($this->M << 3) | ($this->L - 1)) . $this->nonce . $lenM;

        // Encode "l(a)"
        if ($lenA < ((1 << 16) - (1 << 8))) {
            // 0 < l(a) < 2**16 - 2**8
            $b .= pack("n", $lenA);
        } elseif (($lenA >> 32) === 0) {
            // 2**16 - 2**8 <= l(a) < 2**32
            $b .= pack("nN", 0xFEFF, $lenA);
        } else {
            // Messages with l(a) >= 2**32 are not supported yet
            throw new \RuntimeException('Not implemented yet');
        }

        // Encode "a" and add padding if necessary
        $b .= $A;
        $b .= str_repeat("\x00", (16 - (strlen($b) % 16)) % 16);

        // Encode "m" and add padding if necessary
        $b .= $M;
        $b .= str_repeat("\x00", (16 - (strlen($b) % 16)) % 16);

        // Compute the checksum "X"
        $X = str_repeat("\x00", 16);
        foreach (str_split($b, 16) as $block) {
            $X = $this->cipher->encrypt('', $X ^ $block);
        }
        $T = substr($X, 0, ($this->M << 1) + 2);
        return $T;
    }

    /// Increment the value of the counter by one.
    protected function incrementCounter($c)
    {
        for ($i = $this->L - 1; $i >= 0; $i--) {
            // chr() takes care of overflows automatically.
            $c[$i] = chr(ord($c[$i]) + 1);

            // Stop, unless the incremented generated an overflow.
            // In that case, we continue to propagate the carry.
            if ("\x00" !== $c[$i]) {
                break;
            }
        }
        return $c;
    }


    public function encrypt($data, $context)
    {
        $options    = stream_context_get_options($context);
        $Adata      = isset($options['cryptal']['data']) ? (string) $options['cryptal']['data'] : '';
        $counter    = str_repeat("\x00", $this->L);
        $a          = chr($this->L - 1) . $this->nonce; // Flags & nonce
        $S0         = $this->cipher->encrypt('', $a . $counter);

        $res = '';
        foreach (str_split($data, 16) as $block) {
            $counter    = $this->incrementCounter($counter);
            $res       .= $block ^ $this->cipher->encrypt('', $a . $counter);
        }

        stream_context_set_option($context, 'cryptal', 'tag', $this->checkum($data, $Adata) ^ $S0);
        return $res;
    }

    public function decrypt($data, $context)
    {
        $options    = stream_context_get_options($context);
        $Adata      = isset($options['cryptal']['data']) ? (string) $options['cryptal']['data'] : '';
        $T          = isset($options['cryptal']['tag']) ? (string) $options['cryptal']['tag'] : '';
        $counter    = str_repeat("\x00", $this->L);
        $a          = chr($this->L - 1) . $this->nonce; // Flags & nonce
        $S0         = $this->cipher->encrypt('', $a . $counter);

        $res = '';
        foreach (str_split($data, 16) as $block) {
            $counter    = $this->incrementCounter($counter);
            $res       .= $block ^ $this->cipher->encrypt('', $a . $counter);
        }

        $T2 = $this->checkum($res, $Adata) ^ $S0;
        if ($T2 !== $T) {
            throw new \InvalidArgumentException('Tag does not match expected value');
        }
        return $res;
    }
}
