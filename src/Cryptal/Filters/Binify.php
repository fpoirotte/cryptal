<?php

namespace fpoirotte\Cryptal\Filters;

class Binify extends \php_user_filter
{
    protected $buffer;

    public function onCreate()
    {
        $this->buffer = '';
    }

    public function filter($in, $out, &$consumed, $closing)
    {
        $res        = PSFS_FEED_ME;
        while (true) {
            $bucket = stream_bucket_make_writeable($in);
            if ($bucket) {
                $this->buffer .= $bucket->data;
            }


            $available = strlen($this->buffer);
            if ($available >= 2) {
                $consume        = $available - ($available % 2);
                $data           = substr($this->buffer, 0, $consume);

                if (strspn($data, '1234567890abcdefABCDEF') !== $consume) {
                    // The input contains non-hexadecimal data.
                    throw new \RuntimeException('Invalid data in input');
                }

                $outBucket  = stream_bucket_new($this->stream, pack('H*', $data));
                stream_bucket_append($out, $outBucket);

                $this->buffer   = (string) substr($this->buffer, $consume);
                $consumed      += $consume;
                $res            = PSFS_PASS_ON;
            }

            if (!$bucket) {
                if ($closing && $this->buffer !== '') {
                    // The input contains an odd number of bytes and is thus invalid.
                    throw new \RuntimeException('Odd number of bytes in input');
                }

                return $res;
            }
        }
    }
}
