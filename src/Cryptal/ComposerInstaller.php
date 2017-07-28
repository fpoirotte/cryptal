<?php

namespace fpoirotte\Cryptal;

use Composer\Autoload\ClassLoader;
use Composer\Installer\LibraryInstaller;
use Composer\Repository\InstalledRepositoryInterface;
use Composer\Package\PackageInterface;
use fpoirotte\Cryptal\Registry;
use fpoirotte\Cryptal\RegistryWrapper;

/**
 * Composer installer that keeps track of installed cryptographic
 * primitives using a central registry.
 */
class ComposerInstaller extends LibraryInstaller
{
    private function callEntryPoints($eps, $autoload, $wrapper)
    {
        $loader = new ClassLoader();
        if (isset($autoload['psr-0'])) {
            foreach ($autoload['psr-0'] as $prefix => $path) {
                $loader->set($prefix, $path);
            }
        }
        if (isset($autoload['psr-4'])) {
            foreach ($autoload['psr-4'] as $prefix => $path) {
                $loader->setPsr4($prefix, $path);
            }
        }

        foreach ((array) $eps as $ep) {
            if (!class_exists($ep, false)) {
                $loader->loadClass($ep);
            }

            $interfaces = (array) class_implements($ep);
            if (!in_array('fpoirotte\\Cryptal\\Implementers\\PluginInterface', $interfaces)) {
                throw new \InvalidArgumentException('Invalid entry point: ' . $ep);
            }

            call_user_func("$ep::registerAlgorithms", $wrapper);
        }
    }

    public function install(InstalledRepositoryInterface $repo, PackageInterface $package)
    {
        $extra = $package->getExtra();
        if (empty($extra['cryptal.entrypoint'])) {
            throw new \UnexpectedValueException('Error while installing ' . $package->getPrettyName() .
                                                ', cryptal-plugin packages should have an entry point ' .
                                                'defined in their extra key to be usable.');
        }

        $res = parent::install($repo, $package);

        try {
            $registry   = Registry::getInstance();
            $wrapper    = new RegistryWrapper($registry, $package->getPrettyName());
            $this->callEntryPoints($extra['cryptal.entrypoint'], $package->getAutoload(), $wrapper);
            $registry->save();
        } catch (\Exception $e) {
            $this->io->writeError('Cryptal plugin installation failed, rolling back');
            parent::uninstall($repo, $package);
            throw $e;
        }

        return $res;
    }

    public function update(InstalledRepositoryInterface $repo, PackageInterface $initial, PackageInterface $target)
    {
        $extra = $target->getExtra();
        if (empty($extra['cryptal.entrypoint'])) {
            throw new \UnexpectedValueException('Error while installing ' . $target->getPrettyName() .
                                                ', cryptal-plugin packages should have an entry point ' .
                                                'defined in their extra key to be usable.');
        }

        $res = parent::update($repo, $initial, $target);

        try {
            $registry = Registry::getInstance();
            $registry->removeAlgorithms($initial->getPrettyName());
            $wrapper = new RegistryWrapper($registry, $target->getPrettyName());
            $this->callEntryPoints($extra['cryptal.entrypoint'], $target->getAutoload(), $wrapper);
            $registry->save();
        } catch (\Exception $e) {
            $this->io->writeError('Cryptal plugin update failed, rolling back');
            parent::install($repo, $initial);
            throw $e;
        }

        return $res;
    }

    public function uninstall(InstalledRepositoryInterface $repo, PackageInterface $package)
    {
        $res = parent::uninstall($repo, $package);
        $registry = Registry::getInstance();
        $registry->removeAlgorithms($package->getPrettyName());
        $registry->save();
        return $res;
    }

    public function supports($packageType)
    {
        return 'cryptal-plugin' === $packageType;
    }

    public function registerRootPackage(PackageInterface $package)
    {
        $extra = $package->getExtra();
        if (empty($extra['cryptal.entrypoint'])) {
            throw new \UnexpectedValueException('Error while installing ' . $package->getPrettyName() .
                                                ', cryptal-plugin packages should have an entry point ' .
                                                'defined in their extra key to be usable.');
        }

        try {
            $registry = Registry::getInstance();
            $registry->removeAlgorithms($package->getPrettyName());
            $wrapper = new RegistryWrapper($registry, $package->getPrettyName());
            $this->callEntryPoints($extra['cryptal.entrypoint'], $package->getAutoload(), $wrapper);
            $registry->save();
        } catch (\Exception $e) {
            $this->io->writeError('Cryptal plugin registration failed');
            throw $e;
        }
    }
}
