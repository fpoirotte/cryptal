<?php

namespace fpoirotte\Cryptal\Filters;

class Hexify extends \php_user_filter
{
    public function filter($in, $out, &$consumed, $closing)
    {
        while ($bucket = stream_bucket_make_writeable($in)) {
            $consumed  += $bucket->datalen;
            $outBucket  = stream_bucket_new($this->stream, bin2hex($bucket->data));
            stream_bucket_append($out, $outBucket);
        }
        return PSFS_PASS_ON;
    }
}
