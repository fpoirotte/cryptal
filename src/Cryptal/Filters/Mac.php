<?php

namespace fpoirotte\Cryptal\Filters;

use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;

class Mac extends \php_user_filter
{
    protected $context;

    public function onCreate()
    {
        if (!isset($this->params['algorithm']) ||
            !is_object($this->params['algorithm']) ||
            !($this->params['algorithm'] instanceof MacEnum)) {
            throw new \InvalidArgumentException('Invalid algorithm');
        }

        if (!isset($this->params['innerAlgorithm']) ||
            !is_object($this->params['innerAlgorithm']) ||
            !($this->params['innerAlgorithm'] instanceof SubAlgorithmAbstractEnum)) {
            throw new \InvalidArgumentException('Invalid inner algorithm');
        }

        if (!isset($this->params['key']) || !is_string($this->params['key'])) {
            throw new \InvalidArgumentException('Missing or invalid key');
        }

        $nonce = isset($this->params['nonce']) ? $this->params['nonce'] : '';
        if (!is_string($nonce)) {
            throw new \InvalidArgumentException('Invalid nonce');
        }

        $allowUnsafe    = isset($this->params['allowUnsafe']) ? (bool) $this->params['allowUnsafe'] : false;
        $this->context  = Registry::buildMac(
            $this->params['algorithm'],
            $this->params['innerAlgorithm'],
            $this->params['key'],
            $nonce,
            $allowUnsafe
        );
        return true;
    }

    public function filter($in, $out, &$consumed, $closing)
    {
        while ($bucket = stream_bucket_make_writeable($in)) {
            $this->context->update($bucket->data);
            $consumed += $bucket->datalen;
        }

        if ($closing) {
            $bucket = stream_bucket_new($this->stream, $this->context->finalize(true));
            stream_bucket_append($out, $bucket);
        }

        return PSFS_PASS_ON;
    }
}
