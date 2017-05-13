<?php

namespace fpoirotte\Cryptal;

class CryptoStream
{
    public $context;
    protected $done;
    protected $buffer;
    protected $mode;
    protected $padding;
    protected $method;
    protected $direction;
    protected $blockSize;
    const DEBUG = true;

    // @codingStandardsIgnoreStart
    public function stream_eof()
    {
        // @codingStandardsIgnoreEnd
        return $this->done && !strlen($this->buffer);
    }

    // @codingStandardsIgnoreStart
    public function stream_open($path, $mode, $options, &$opened_path)
    {
        // @codingStandardsIgnoreEnd
        if (null === $this->context) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Missing cryptographic context', E_USER_ERROR);
            }
            return false;
        }
        $ctxOptions = stream_context_get_options($this->context);

        if (false === strpos($mode, '+')) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Invalid mode', E_USER_ERROR);
            }
            return false;
        }

        $iv = '';
        if (isset($ctxOptions['cryptal']['IV'])) {
            $iv = (string) $ctxOptions['cryptal']['IV'];
        }

        $tagLength = 0;
        if (isset($ctxOptions['cryptal']['tagLength'])) {
            $tagLength = (int) $ctxOptions['cryptal']['tagLength'];
        }

        $padding = new \fpoirotte\Cryptal\Padding\Zero();
        if (isset($ctxOptions['cryptal']['padding'])) {
            $padding = $ctxOptions['cryptal']['padding'];
        }

        if (!isset($ctxOptions['cryptal']['key'])) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Invalid cryptographic context', E_USER_ERROR);
            }
            return false;
        }

        if ($tagLength < 0) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Invalid tag length', E_USER_ERROR);
            }
            return false;
        }

        if (!($padding instanceof \fpoirotte\Cryptal\PaddingInterface)) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Invalid padding scheme', E_USER_ERROR);
            }
            return false;
        }

        $parts = parse_url($path);
        if ($parts === false) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Invalid path', E_USER_ERROR);
            }
            return false;
        }

        if (!strncasecmp($parts['host'], 'MODE_', 5)) {
            $mode = $parts['host'];
        } else {
            $mode = 'MODE_' . strtoupper($parts['host']);
        }

        if (!strncasecmp($parts['path'], '/CIPHER_', 8)) {
            $cipher = substr($parts['path'], 1);
        } else {
            $cipher = 'CIPHER_' . strtoupper(substr($parts['path'], 1));
        }

        $mode   = '\\fpoirotte\\Cryptal\\Implementation::' . $mode;
        $cipher = '\\fpoirotte\\Cryptal\\Implementation::' . $cipher;
        if (!defined($mode) || !defined($cipher)) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Invalid mode/cipher', E_USER_ERROR);
            }
            return false;
        }

        $this->padding      = $padding;
        $this->buffer       = '';
        $this->done         = false;
        $this->direction    = $parts['scheme'];

        try {
            $impl = new \fpoirotte\Cryptal\Implementation(
                constant($cipher),
                \fpoirotte\Cryptal\CryptoInterface::MODE_ECB,
                new \fpoirotte\Cryptal\Padding\None
            );
            $this->blockSize = $impl->getBlockSize();
        } catch (\Exception $e) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Could not create data processor: ' . $e, E_USER_WARNING);
            }
            return false;
        }

        try {
            // Remove the "Implementation::MODE_" prefix.
            $mode = "\\fpoirotte\\Cryptal\\CryptoStream\\" .
                substr($mode, strlen("\\fpoirotte\\Cryptal\\Implementation::MODE_"));
            $this->mode = new $mode(
                $impl,
                $ctxOptions['cryptal']['key'],
                $iv,
                $tagLength
            );
        } catch (\Exception $e) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Could not create operation mode: ' . $e, E_USER_WARNING);
            }
            return false;
        }

        // Some modes of operation use the exact same process for both
        // encryption & decryption (eg. OFB, CTR, ...).
        // We just redirect the call for those modes to avoid code duplication.
        if ('cryptal.decrypt' === $parts['scheme'] && method_exists($this->mode, 'decrypt')) {
            $this->method = 'decrypt';
        } else {
            $this->method = 'encrypt';
        }

        // Update the context with the actual padding scheme in use.
        stream_context_set_option($this->context, 'cryptal', 'padding', $padding);

        $opened_path = $path;
        return true;
    }

    // @codingStandardsIgnoreStart
    public function stream_read($count)
    {
        // @codingStandardsIgnoreEnd

        if ($count < 2 * $this->blockSize) {
            return false;
        }

        $nbBlocks = (int) strlen($this->buffer) / $this->blockSize;

        // We do not have enough data in the buffer yet.
        if (!$this->done && $nbBlocks < 2) {
            return "";
        }

        if (!$nbBlocks) {
            return "";
        }

        // Number of blocks we would like to keep in the buffer.
        $target = 2;
        if ($this->done) {
            if ('cryptal.decrypt' === $this->direction && $nbBlocks <= 2 ||
                'cryptal.encrypt' === $this->direction) {
                $target = 0;
            }
        }

        // Encrypt/decrypt as much blocks as possible,
        // while still retaining enough data in the buffer.
        $method = $this->method;
        $res    = '';
        for ($i = 0; $i < 2 && $nbBlocks > $target; $i++, $nbBlocks--) {
            $block          = (string) substr($this->buffer, 0, $this->blockSize);
            $this->buffer   = (string) substr($this->buffer, $this->blockSize);
            $res           .= $this->mode->$method($block, $this->context);
        }

        if ('cryptal.decrypt' === $this->direction && 0 === $target && 0 === $nbBlocks) {
            // We were decrypting the last blocks.
            // Remove the padding and return the final result.
            $padLen = $this->padding->getPaddingSize($res, $this->blockSize);
            return $padLen ? (string) substr($res, 0, -$padLen) : $res;
        }

        return $res;
    }

    // @codingStandardsIgnoreStart
    public function stream_flush()
    {
        // @codingStandardsIgnoreEnd
        if ($this->done) {
            return false;
        }

        // Add a padding only when encrypting.
        if ('cryptal.encrypt' === $this->direction) {
            $missing = $this->blockSize - (strlen($this->buffer) % $this->blockSize);
            $this->buffer .= $this->padding->getPaddingData($this->blockSize, $missing);
        }

        $this->done = true;
        return true;
    }

    // @codingStandardsIgnoreStart
    public function stream_write($data)
    {
        // @codingStandardsIgnoreEnd
        if ($this->done) {
            return 0;
        }

        $this->buffer .= $data;
        return strlen($data);
    }
}
