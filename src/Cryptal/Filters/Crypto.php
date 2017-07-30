<?php

namespace fpoirotte\Cryptal\Filters;

use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\AsymmetricModeInterface;
use fpoirotte\Cryptal\Implementers\CryptoInterface;

class Crypto extends \php_user_filter
{
    protected $blockSize;
    protected $padding;
    protected $mode;
    protected $method;
    protected $buffer;

    public function onCreate()
    {
        if (!isset($this->params['algorithm']) ||
            !is_object($this->params['algorithm']) ||
            !($this->params['algorithm'] instanceof CipherEnum)) {
            throw new \InvalidArgumentException('Invalid algorithm');
        }

        if (!isset($this->params['mode']) ||
            !is_object($this->params['mode']) ||
            !($this->params['mode'] instanceof ModeEnum)) {
            throw new \InvalidArgumentException('Invalid mode');
        }

        if (!isset($this->params['key']) || !is_string($this->params['key'])) {
            throw new \InvalidArgumentException('Missing or invalid key');
        }

        $padding = new \fpoirotte\Cryptal\Padding\None();
        if (isset($this->params['padding'])) {
            $padding = $this->params['padding'];
        }
        if (!is_object($padding) || !($padding instanceof PaddingInterface)) {
            throw new \InvalidArgumentException('Invalid padding scheme');
        }

        $tagLength = CryptoInterface::DEFAULT_TAG_LENGTH;
        if (isset($this->params['tagLength'])) {
            $tagLength = $this->params['tagLength'];
        }
        if (!is_integer($tagLength) || $tagLength < 0) {
            throw new \InvalidArgumentException('Invalid tag length');
        }

        $iv = isset($this->params['iv']) ? $this->params['iv'] : '';
        if (!is_string($iv)) {
            throw new \InvalidArgumentException('Invalid initialization vector');
        }

        // Make sure the selected mode is supported.
        if (!isset($this->params['mode'])) {
            throw new \InvalidArgumentException('No mode specified');
        }
        $mode = "\\fpoirotte\\Cryptal\\Modes\\" . substr($this->params['mode'], strlen('MODE_'));
        $interfaces = class_implements($mode, true);
        if (!$interfaces || !in_array("fpoirotte\Cryptal\SymmetricModeInterface", $interfaces)) {
            throw new \InvalidArgumentException('Unsupported mode');
        }

        $allowUnsafe    = isset($this->params['allowUnsafe']) ? (bool) $this->params['allowUnsafe'] : false;
        $cipher         = Registry::buildCipher(
            $this->params['algorithm'],
            ModeEnum::MODE_ECB(),
            new \fpoirotte\Cryptal\Padding\None(),
            $this->params['key'],
            $tagLength,
            $allowUnsafe
        );

        $this->buffer       = '';
        $this->blockSize    = $cipher->getBlockSize();
        $this->padding      = $padding;
        $this->mode         = new $mode(
            $cipher,
            $iv,
            $tagLength
        );
        if ('cryptal.decrypt' === $this->filtername && $this->mode instanceof AsymmetricModeInterface) {
            $this->method = 'decrypt';
        } else {
            $this->method = 'encrypt';
        }
        return true;
    }

    public function filter($in, $out, &$consumed, $closing)
    {
        $res        = PSFS_FEED_ME;
        $method     = $this->method;
#        $options    = stream_context_get_options($this->stream);

        while (true) {
            $bucket = stream_bucket_make_writeable($in);
            if ($bucket) {
                $this->buffer .= $bucket->data;
            } elseif ('cryptal.encrypt' === $this->filtername && $closing) {
                // Add the padding scheme
                $missing        = $this->blockSize - (strlen($this->buffer) % $this->blockSize);
                $this->buffer  .= $this->padding->getPaddingData($this->blockSize, $missing);
            }

            $available  = strlen($this->buffer);
            $nbBlocks   = ($available - ($available % $this->blockSize)) / $this->blockSize;

            if ($nbBlocks > 0) {
                $consume        = $nbBlocks * $this->blockSize;
                $outBuffer      = '';
                for ($i = 0; $i < $nbBlocks; $i++) {
                    $outBuffer .= $this->mode->$method(
                        substr($this->buffer, $this->blockSize * $i, $this->blockSize),
                        $this->stream
                    );
                }

                if (!$bucket && 'cryptal.decrypt' === $this->filtername && $closing) {
                    // Remove the padding scheme
                    $padLen = $this->padding->getPaddingSize($outBuffer, $this->blockSize);
                    if ($padLen) {
                        $outBuffer = (string) substr($outBuffer, 0, -$padLen);
                    }
                }

                stream_bucket_append($out, stream_bucket_new($this->stream, $outBuffer));
                $this->buffer   = (string) substr($this->buffer, $consume);
                $consumed      += $consume;
                $res            = PSFS_PASS_ON;
            }

            if (!$bucket) {
                return $res;
            }
        }
    }
}
