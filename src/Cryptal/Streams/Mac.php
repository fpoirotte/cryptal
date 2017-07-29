<?php

namespace fpoirotte\Cryptal\Streams;

use fpoirotte\Cryptal\Implementers\CryptoInterface;

/**
 * Stream wrapper for Message Authentication Codes.
 */
class Mac
{
    /// Stream context
    public $context;

    /// Data processor
    protected $implementation;

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
        return false;
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

        if (!isset($ctxOptions['cryptal']['key'])) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Invalid cryptographic context', E_USER_ERROR);
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

        if (!strncasecmp($parts['host'], 'MAC_', 4)) {
            $algo = $parts['host'];
        } else {
            $algo = 'MAC_' . strtoupper($parts['host']);
        }

        $algo = '\\fpoirotte\\Cryptal\\Implementers\\Mac::' . $algo;
        if (!defined($algo)) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Invalid MAC algorithm', E_USER_ERROR);
            }
            return false;
        }

        if (!strncasecmp($parts['path'], '/HASH_', 6)) {
            $hash = '\\fpoirotte\\Cryptal\\Implementers\\Hash::' . substr($parts['path'], 1);
            if (!defined($hash)) {
                if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                    trigger_error('Invalid hashing algorithm', E_USER_ERROR);
                }
                return false;
            }

            $sub = new \fpoirotte\Cryptal\Implementers\Hash(constant($hash));
        } elseif (!strncasecmp($parts['path'], '/CIPHER_', 8)) {
            $cipher = '\\fpoirotte\\Cryptal\\Implementers\\Crypto::' . substr($parts['path'], 1);
            if (!defined($cipher)) {
                if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                    trigger_error('Invalid cipher algorithm', E_USER_ERROR);
                }
                return false;
            }

            $sub = new \fpoirotte\Cryptal\Implementers\Crypto(
                constant($cipher),
                CryptoInterface::MODE_ECB,
                new \fpoirotte\Cryptal\Padding\None()
            );
        }

        $allowUnsafe        = isset($ctxOptions['cryptal']['allowUnsafe']) ?
                              (bool) $ctxOptions['cryptal']['allowUnsafe'] : false;
        try {
            $this->implementation = new \fpoirotte\Cryptal\Implementers\Mac(
                constant($algo),
                $sub,
                $ctxOptions['cryptal']['key']
            );
        } catch (\Exception $e) {
            if (self::DEBUG || $options & STREAM_REPORT_ERRORS) {
                trigger_error('Could not create data processor: ' . $e, E_USER_WARNING);
            }
            return false;
        }

        $opened_path = $path;
        return true;
    }

    // @codingStandardsIgnoreStart
    /**
     * Read data from the stream.
     *
     * \param int $count
     *      Requested read count. This value must be large enough
     *      to hold the whole Message Authentication Code.
     *
     * \retval bool
     *      \b false is returned on error (eg. when the requested
     *      read count is too small).
     *
     * \retval string
     *      Authentication Code for the message fed to the data processor
     *      so far, in raw (binary) form.
     */
    public function stream_read($count)
    {
        // @codingStandardsIgnoreEnd

        $clone  = clone $this->implementation;
        $result = $clone->finalize(true);
        return strlen($result) > $count ? false : $result;
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

        $this->implementation->update($data);
        return strlen($data);
    }
}
