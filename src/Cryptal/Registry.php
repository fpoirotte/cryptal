<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\Implementers\HashInterface;
use fpoirotte\Cryptal\Implementers\MacInterface;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\MacEnum;

/**
 * A registry/factory for cryptographic primitives.
 */
class Registry
{
    /**
     *  Stores metadata about supported algorithms.
     *
     *  Looks somewhat like this, except that the constants
     *  are replaced with their actual values:
     *
     *  \code
     *  array(
     *      'crypt' => array(
     *          CIPHER_3DES . ':' . MODE_CTR => array(
     *              array('vendor/pluginname', 'Vendor\\PluginName\\SomeClass', TYPE_ASSEMBLY),
     *              ...
     *          ),
     *          ...
     *      ),
     *      'hash' => array(
     *          HASH_MD5 => array(
     *              ...
     *          ),
     *          ...
     *      ),
     *      'mac' => ...,
     *  );
     *  \endcode
     */
    private $metadata;

    static private $path = null;

    public function __construct()
    {
        if (null === self::$path) {
            $registryPath = getenv('CRYPTAL_REGISTRY');
            if (false === $registryPath || '' === $registryPath) {
                self::$path = __DIR__ . DIRECTORY_SEPARATOR . 'registry.dat';
            } else {
                self::$path = $registryPath;
            }
        }

        $this->load(true);
    }

    public static function getInstance()
    {
        static $instance = null;
        if (null === $instance) {
            $instance = new static;
        }
        return $instance;
    }

    public function addCipher($packageName, $cls, CipherEnum $cipher, ModeEnum $mode, ImplementationTypeEnum $type)
    {
        $ifaces = class_implements($cls);
        $iface  = 'fpoirotte\\Cryptal\\Implementers\\CryptoInterface';
        if (!$ifaces || !in_array($iface, $ifaces)) {
            throw new \InvalidArgumentException("$cls does not implement $iface");
        }
        $this->metadata['crypt']["$cipher:$mode"][] = array($packageName, $cls, $type);
    }

    public function addHash($packageName, $cls, HashEnum $algo, ImplementationTypeEnum $type)
    {
        $ifaces = class_implements($cls);
        $iface  = 'fpoirotte\\Cryptal\\Implementers\\HashInterface';
        if (!$ifaces || !in_array($iface, $ifaces)) {
            throw new \InvalidArgumentException("$cls does not implement $iface");
        }
        $this->metadata['hash']["$algo"][] = array($packageName, $cls, $type);
    }

    public function addMac($packageName, $cls, MacEnum $algo, ImplementationTypeEnum $type)
    {
        $ifaces = class_implements($cls);
        $iface  = 'fpoirotte\\Cryptal\\Implementers\\MacInterface';
        if (!$ifaces || !in_array($iface, $ifaces)) {
            throw new \InvalidArgumentException("$cls does not implement $iface");
        }
        $this->metadata['mac']["$algo"][] = array($packageName, $cls, $type);
    }

    public function removeAlgorithms($packageName)
    {
        foreach ($this->metadata as &$algoTypes) {
            foreach ($algoTypes as &$algos) {
                foreach ($algos as $key => $desc) {
                    if ($desc[0] === $packageName) {
                        unset($algos[$key]);
                    }
                }
            }
        }
    }

    public function load($registerDefaultAlgorithms = true)
    {
        $data = @file_get_contents(self::$path);
        if (false === $data) {
            $this->reset();
        } else {
            $this->metadata = unserialize($data);
            $this->removeAlgorithms('');
        }

        if ($registerDefaultAlgorithms) {
            // Ciphers
            $this->addCipher(
                '',
                'fpoirotte\\Cryptal\\DefaultAlgorithms\\ChaCha20Openssh',
                CipherEnum::CIPHER_CHACHA20_OPENSSH(),
                ModeEnum::MODE_ECB(),
                ImplementationTypeEnum::TYPE_USERLAND()
            );
            $camellia = array(
                CipherEnum::CIPHER_CAMELIA_128(),
                CipherEnum::CIPHER_CAMELIA_192(),
                CipherEnum::CIPHER_CAMELIA_256(),
            );
            foreach ($camellia as $cipher) {
                $this->addCipher(
                    '',
                    'fpoirotte\\Cryptal\\DefaultAlgorithms\\Camellia',
                    $cipher,
                    ModeEnum::MODE_ECB(),
                    ImplementationTypeEnum::TYPE_USERLAND()
                );
            }

            // Hashes
            $algos = array(
                HashEnum::HASH_CRC32(),
                HashEnum::HASH_MD5(),
                HashEnum::HASH_SHA1(),
            );
            foreach ($algos as $algo) {
                $this->addHash(
                    '',
                    'fpoirotte\\Cryptal\\DefaultAlgorithms\\Hash',
                    $algo,
                    ImplementationTypeEnum::TYPE_COMPILED()
                );
            }

            // MACs
            $this->addMac(
                '',
                'fpoirotte\\Cryptal\\DefaultAlgorithms\\Cmac',
                MacEnum::MAC_CMAC(),
                ImplementationTypeEnum::TYPE_USERLAND()
            );
            $this->addMac(
                '',
                'fpoirotte\\Cryptal\\DefaultAlgorithms\\Poly1305',
                MacEnum::MAC_POLY1305(),
                ImplementationTypeEnum::TYPE_USERLAND()
            );
            $algos = array(
                MacEnum::MAC_UMAC_32(),
                MacEnum::MAC_UMAC_64(),
                MacEnum::MAC_UMAC_96(),
                MacEnum::MAC_UMAC_128(),
            );
            foreach ($algos as $algo) {
                $this->addMac(
                    '',
                    'fpoirotte\\Cryptal\\DefaultAlgorithms\\Umac',
                    $algo,
                    ImplementationTypeEnum::TYPE_USERLAND()
                );
            }
        }
    }

    public function save()
    {
        file_put_contents(self::$path, serialize($this->metadata));
    }

    protected static function findCipher(CipherEnum $cipher, ModeEnum $mode, $allowUnsafe)
    {
        $registry = self::getInstance();
        $res = array(
            (string) ImplementationTypeEnum::TYPE_ASSEMBLY() => null,
            (string) ImplementationTypeEnum::TYPE_COMPILED() => null,
            (string) ImplementationTypeEnum::TYPE_USERLAND() => null,
        );

        if (empty($registry->metadata['crypt']["$cipher:$mode"])) {
            throw new \Exception('Unsupported cipher/mode combination');
        }

        foreach ($registry->metadata['crypt']["$cipher:$mode"] as $impl) {
            $res["${impl[2]}"] = $impl[1];
        }

        foreach ($res as $type => $cls) {
            if (null !== $cls) {
                if ($type == (string) ImplementationTypeEnum::TYPE_USERLAND() && !$allowUnsafe) {
                    throw new \Exception('No safe implementation found for cipher/mode');
                }

                return $cls;
            }
        }

        throw new \Exception('Unsupported cipher/mode combination');
    }

    public static function buildCipher(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = CryptoInterface::DEFAULT_TAG_LENGTH,
        $allowUnsafe = false
    ) {
        if (!is_string($key)) {
            throw new \InvalidArgumentException('Invalid key');
        }

        if (!is_int($tagLength) || 0 > $tagLength) {
            throw new \InvalidArgumentException('Invalid tag length');
        }

        $cls = self::findCipher($cipher, $mode, $allowUnsafe);
        return new $cls($cipher, $mode, $padding, $key, $tagLength);
    }

    protected static function findHash(HashEnum $algo, $allowUnsafe)
    {
        $registry = self::getInstance();
        $res = array(
            (string) ImplementationTypeEnum::TYPE_ASSEMBLY() => null,
            (string) ImplementationTypeEnum::TYPE_COMPILED() => null,
            (string) ImplementationTypeEnum::TYPE_USERLAND() => null,
        );

        if (empty($registry->metadata['hash']["$algo"])) {
            throw new \Exception('Unsupported hash algorithm');
        }

        foreach ($registry->metadata['hash']["$algo"] as $impl) {
            $res["${impl[2]}"] = $impl[1];
        }

        foreach ($res as $type => $cls) {
            if (null !== $cls) {
                if ($type == (string) ImplementationTypeEnum::TYPE_USERLAND() && !$allowUnsafe) {
                    throw new \Exception('No safe implementation found for hash');
                }

                return $cls;
            }
        }

        throw new \Exception('Unsupported hash algorithm');
    }

    public static function buildHash(HashEnum $algo, $allowUnsafe = false)
    {
        $cls = self::findHash($algo, $allowUnsafe);
        return new $cls($algo);
    }

    protected static function findMac(MacEnum $algo, $allowUnsafe)
    {
        $registry = self::getInstance();

        $res = array(
            (string) ImplementationTypeEnum::TYPE_ASSEMBLY() => null,
            (string) ImplementationTypeEnum::TYPE_COMPILED() => null,
            (string) ImplementationTypeEnum::TYPE_USERLAND() => null,
        );

        if (empty($registry->metadata['mac']["$algo"])) {
            throw new \Exception('Unsupported MAC algorithm');
        }

        foreach ($registry->metadata['mac']["$algo"] as $impl) {
            $res["${impl[2]}"] = $impl[1];
        }

        foreach ($res as $type => $cls) {
            if (null !== $cls) {
                if ($type == (string) ImplementationTypeEnum::TYPE_USERLAND() && !$allowUnsafe) {
                    throw new \Exception('No safe implementation found for MAC');
                }

                return $cls;
            }
        }

        throw new \Exception('Unsupported MAC algorithm');
    }

    public static function buildMac(
        MacEnum $algo,
        SubAlgorithmAbstractEnum $subAlgo,
        $key,
        $nonce = '',
        $allowUnsafe = false
    ) {
        if (!is_string($key)) {
            throw new \InvalidArgumentException('Invalid key');
        }

        if (!is_string($nonce)) {
            throw new \InvalidArgumentException('Invalid nonce');
        }

        if ($subAlgo instanceof HashEnum) {
            self::findHash($subAlgo, $allowUnsafe);
        } elseif ($subAlgo instanceof CipherEnum) {
            self::findCipher($subAlgo, ModeEnum::MODE_ECB(), $allowUnsafe);
        } else {
            throw new \InvalidArgumentException('Invalid inner algorithm');
        }

        $cls = self::findMac($algo, $allowUnsafe);
        return new $cls($algo, $subAlgo, $key, $nonce);
    }

    public function reset()
    {
        $this->metadata = array(
            'crypt' => array(),
            'hash'  => array(),
            'mac'   => array(),
        );
    }

    public function getSupportedCiphers()
    {
        $res = array();
        foreach ($this->metadata['crypt'] as $algo => $dummy) {
            list($cipher, $mode) = explode(':', $algo);
            $res[] = array(CipherEnum::$cipher(), ModeEnum::$mode());
        }
        return $res;
    }

    public function getSupportedHashes()
    {
        $res = array();
        foreach ($this->metadata['hash'] as $algo => $dummy) {
            $res[] = HashEnum::$algo();
        }
        return $res;
    }

    public function getSupportedMacs()
    {
        $res = array();
        foreach ($this->metadata['mac'] as $algo => $dummy) {
            $res[] = MacEnum::$algo();
        }
        return $res;
    }
}
