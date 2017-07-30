<?php

namespace fpoirotte\Cryptal\Filters;

class Hexify extends \php_user_filter
{
    protected $uppercase;

    public function onCreate()
    {
        $this->uppercase = isset($this->params['uppercase']) ? (bool) $this->params['uppercase'] : false;
    }

    public function filter($in, $out, &$consumed, $closing)
    {
        while ($bucket = stream_bucket_make_writeable($in)) {
            $consumed  += $bucket->datalen;
            $output     = bin2hex($bucket->data);

            if ($this->uppercase) {
                $output = strtoupper($output);
            }

            $outBucket  = stream_bucket_new($this->stream, $output);
            stream_bucket_append($out, $outBucket);
        }
        return PSFS_PASS_ON;
    }
}
