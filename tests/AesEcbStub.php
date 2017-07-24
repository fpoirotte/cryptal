<?php

namespace fpoirotte\Cryptal\Tests;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\SubAlgorithmInterface;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;

class AesEcbStub implements CryptoInterface
{
    protected   $map;
    private     $key;
    protected   $cipher;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        $supported = array(
            CipherEnum::CIPHER_AES_128(),
            CipherEnum::CIPHER_AES_192(),
            CipherEnum::CIPHER_AES_256(),
        );

        if (!in_array($cipher, $supported) || ModeEnum::MODE_ECB() != $mode || !($padding instanceof None)) {
            throw new \InvalidArgumentException('Invalid cipher, mode or padding');
        }

        $it = new \GlobIterator(__DIR__ . DIRECTORY_SEPARATOR . 'aes_ecb' . DIRECTORY_SEPARATOR . '*.dat');
        foreach ($it as $file) {
            $loadedKey              = basename($file, '.dat');
            $this->map[$loadedKey]  = array();

            foreach (file($file) as $lineno => $line) {
                $line = trim($line);
                if ('' === $line || !strncmp($line, '#', 1)) {
                    continue;
                }

                if (false === strpos($line, ' ')) {
                    $no = $lineno + 1;
                    throw new \Exception("Invalid data in $file on line $no: $line");
                }

                list($input, $output) = explode(' ', $line);
                $this->map[$loadedKey][$input] = $output;
            }
        }

        if (!isset($this->map[bin2hex($key)])) {
            throw new \InvalidArgumentException('Unsupported key: ' . bin2hex($key));
        }

        $this->key      = $key;
        $this->cipher   = $cipher;
    }

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        $key    = bin2hex($this->key);
        $data   = bin2hex($data);
        if (isset($this->map[$key][$data])) {
            return pack('H*', $this->map[$key][$data]);
        }
        $known  = implode("', '", array_keys($this->map));
        throw new \Exception("Unknown key or plaintext: key='$key', plaintext='$data', known_keys=('$known')");
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {
        $key    = bin2hex($this->key);
        $data   = bin2hex($data);

        if (!isset($this->map[$key])) {
            $known  = implode("', '", array_keys($this->map));
            throw new \Exception("Unknown key or plaintext: key='$key', ciphertext='$data', known_keys=('$known')");
        }

        $res    = array_search($data, $this->map[$key]);
        if (false !== $res) {
            return pack('H*', $res);
        }

        $known  = implode("', '", array_keys($this->map));
        throw new \Exception("Unknown key or plaintext: key='$key', ciphertext='$data', known_keys=('$known')");
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
