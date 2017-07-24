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
use fpoirotte\Cryptal\DefaultAlgorithms\ChaCha20;

/**
 * ChaCha20 block cipher with AEAD (OpenSSH variante).
 *
 * \note
 *      This class implements the AEAD construction defined in
 *      http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305.
 *
 * \see
 *      http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305
 */
class ChaCha20Openssh extends ChaCha20
{
    /// Header encryptor.
    protected $header;

    /// Main encryptor.
    protected $main;

    protected $cipher;
    protected $key;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        if (CipherEnum::CIPHER_CHACHA20_OPENSSH() !== $cipher) {
            throw new \InvalidArgumentException('Unsupported cipher');
        }

        if (!($padding instanceof None)) {
            throw new \InvalidArgumentException(
                'ChaCha20 does not need any padding ' .
                '(hint: use fpoirotte\Cryptal\Padding\None)'
            );
        }

        if (16 !== $tagLength) {
            throw new \InvalidArgumentException('Invalid tag length');
        }

        if (64 !== strlen($key)) {
            throw new \InvalidArgumentException('Invalid key length');
        }

        $this->tagLength    = $tagLength;
        $this->main     = new ChaCha20($cipher, $mode, $padding, substr($key, 0, 32), 0);
        $this->header   = new ChaCha20($cipher, $mode, $padding, substr($key, 32), 0);
        $this->key          = $key;
        $this->cipher       = $cipher;
    }

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        if (strlen($iv) != $this->getIVSize()) {
            throw new \InvalidArgumentException('Invalid Initialization Vector');
        }

        $polyKey    = $this->main->basicXcrypt(str_repeat("\x00", 32), $iv, 0);
        $aad        = $this->header->basicXcrypt($aad, $iv, 0);
        $res        = $this->main->basicXcrypt($data, $iv, 1);

        // @FIXME We should probably use the registry here,
        //        in case a C implementation is available.
        $tag = Poly1305::mac(
            MacEnum::MAC_POLY1305(),
            CipherEnum::CIPHER_CHACHA20(),
            $polyKey,
            $aad . $res,
            '',
            true
        );
        return $res;
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {
        if (strlen($iv) != $this->getIVSize()) {
            throw new \InvalidArgumentException('Invalid Initialization Vector');
        }

        $aad        = $this->header->basicXcrypt($aad, $iv, 0);
        $polyKey    = $this->main->basicXcrypt(str_repeat("\x00", 32), $iv, 0);

        // @FIXME We should probably use the registry here,
        //        in case a C implementation is available.
        $outTag = Poly1305::mac(
            MacEnum::MAC_POLY1305(),
            CipherEnum::CIPHER_CHACHA20(),
            $polyKey,
            $aad . $data,
            '',
            true
        );
        if ($tag !== $outTag) {
            throw new \InvalidArgumentException('Invalid tag');
        }

        return $this->main->basicXcrypt($data, $iv, 1);
    }

    public function getIVSize()
    {
        return 8;
    }
}
