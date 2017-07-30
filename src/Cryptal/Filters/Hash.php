<?php

namespace fpoirotte\Cryptal\Filters;

use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\HashEnum;

class Hash extends \php_user_filter
{
    protected $context;

    public function onCreate()
    {
        if (!isset($this->params['algorithm']) ||
            !is_object($this->params['algorithm']) ||
            !($this->params['algorithm'] instanceof HashEnum)) {
            throw new \InvalidArgumentException('Invalid algorithm');
        }

        $allowUnsafe    = isset($this->params['allowUnsafe']) ? (bool) $this->params['allowUnsafe'] : false;
        $this->context  = Registry::buildHash($this->params['algorithm'], $allowUnsafe);
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
