<?php

namespace fpoirotte\Cryptal\Streams;

use fpoirotte\Cryptal\AsymmetricModeInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\Registry;

/**
 * Stream wrapper for encryption/decryption operations.
 */
class Crypto
{
    /// Stream context
    public $context;

    /// Flag indicating that the stream was flushed
    protected $done;

    /// Internal buffer
    protected $buffer;

    /// Encryption/decryption mode
    protected $mode;

    /// Padding scheme
    protected $padding;

    /// Name of the method to call for the selected mode of operations.
    protected $method;

    /// Name of the stream wrapper (to distinguish encryption from decryption)
    protected $direction;

    /// Cipher's block size
    protected $blockSize;

    /// \internal Force the display of error messages in the stream wrapper.
    const DEBUG = false;

    // @codingStandardsIgnoreStart
    /**
     * Test for end of file (EOF).
     *
     * \çetval bool
     *      \b true if the EOF has been reach, \b false otherwise.
     */
    public function stream_eof()
    {
        // @codingStandardsIgnoreEnd
        return $this->done && !strlen($this->buffer);
    }

    // @codingStandardsIgnoreStart
    /**
     * Open a new stream.
     *
     * \param string $path
     *      URL that was passed to the original function.
     *
     * \param string $mode
     *      Mode used to open the stream.
     *
     * \param int $options
     *      Additional flags set by the streams API.
     *
     * \param string $opened_path
     *      A variable that will be filled with the full path
     *      for the stream on success.
     *
     * \retval bool
     *      \b true on success, \b false on failure.
     */
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
        if ($parts === false || !isset($parts['host'], $parts['path'])) {
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


        $this->padding      = $padding;
        $this->buffer       = '';
        $this->done         = false;
        $this->direction    = $parts['scheme'];
        $allowUnsafe        = isset($ctxOptions['cryptal']['allowUnsafe']) ?
                              (bool) $ctxOptions['cryptal']['allowUnsafe'] : false;

        try {
            $cipherObj = Registry::buildCipher(
                CipherEnum::$cipher(),
                ModeEnum::MODE_ECB(),
                new \fpoirotte\Cryptal\Padding\None,
                $ctxOptions['cryptal']['key'],
                0,
                $allowUnsafe
            );
            $this->blockSize = $cipherObj->getBlockSize();
        } catch (\Exception $e) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Could not create data processor: ' . $e, E_USER_WARNING);
            }
            return false;
        }

        try {
            // Make sure the selected mode is supported.
            $mode = "\\fpoirotte\\Cryptal\\Modes\\" . substr($mode, strlen('MODE_'));
            $interfaces = class_implements($mode, true);
            if (!$interfaces || !in_array("fpoirotte\Cryptal\SymmetricModeInterface", $interfaces)) {
                throw new \Exception('Unsupported mode');
            }

            $this->mode = new $mode(
                $cipherObj,
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
        if ('cryptal.decrypt' === $parts['scheme'] && $this->mode instanceof AsymmetricModeInterface) {
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
    /**
     * Read data from the stream.
     *
     * \param int $count
     *      Requested read count. This value must be large enough
     *      to hold twice the cipher's block size in data.
     *
     * \retval bool
     *      \b false is returned on error (eg. when the requested
     *      read count is too small).
     *
     * \retval string
     *      Data read from the stream. This will be an empty string
     *      if there is not enough data in the stream's buffer yet,
     *      or the encrypted/decrypted data otherwise.
     */
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
    /**
     * Notify the wrapper that no more data will be sent to it.
     *
     * \retval bool
     *      \b true if the notification is acknowledged,
     *      \b false otherwise.
     */
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
    /**
     * Push data into the stream wrapper.
     *
     * \param string $data
     *      Data to add to the stream's buffer.
     *
     * \retval int
     *      Size of the data that's effectively been added
     *      to the buffer. This may be less (even zero)
     *      than the length of the given data.
     */
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
