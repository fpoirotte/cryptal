<?php

namespace fpoirotte\Cryptal;

use Composer\Composer;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginInterface;
use fpoirotte\Cryptal\ComposerInstaller;

class ComposerPlugin implements PluginInterface
{
    public function activate(Composer $composer, IOInterface $io)
    {
        $installer = new ComposerInstaller($io, $composer);
        $composer->getInstallationManager()->addInstaller($installer);

        // Try to register the root package if it is a Cryptal plugin.
        $rootPkg = $composer->getPackage();
        if ($installer->supports($rootPkg->getType())) {
            $installer->registerRootPackage($rootPkg);
        }
    }
}
