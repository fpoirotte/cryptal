<?php

namespace fpoirotte\Cryptal\DefaultAlgorithms;

use fpoirotte\Cryptal\Implementers\AbstractHash;
use fpoirotte\Cryptal\HashEnum;

class Hash extends AbstractHash
{
    private $func;
    private $data;

    public function __construct(HashEnum $algorithm)
    {
        $supported = array(
            'crc32' => HashEnum::HASH_CRC32(),
            'md5'   => HashEnum::HASH_MD5(),
            'sha1'  => HashEnum::HASH_SHA1(),
        );

        $func = array_search($algorithm, $supported);
        if (false === $func) {
            throw new \InvalidArgumentException('Unsupported algorithm');
        }

        $this->func = $func;
        $this->data = '';
    }

    protected function internalUpdate($data)
    {
        $this->data .= $data;
    }

    protected function internalFinalize()
    {
        $func = $this->func;

        if ('crc32' === $func) {
            // For historical reasons, CRC32 is a bit of an oddball.
            return pack('H*', sprintf('%x', crc32($this->data)));
        }

        return call_user_func($func, $this->data, true);
    }
}
