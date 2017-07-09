<?php

$autoload =
    dirname(__DIR__) .
    DIRECTORY_SEPARATOR . 'vendor' .
    DIRECTORY_SEPARATOR . 'autoload.php';

if (file_exists($autoload)) {
    // When running from cryptal's repository.
    require($autoload);
} else {
    // When running from an implementation's repository.
    $autoload =
        dirname(dirname(dirname(__DIR__))) .
        DIRECTORY_SEPARATOR . 'autoload.php';
    require($autoload);
}

require(__DIR__ . DIRECTORY_SEPARATOR . 'api' . DIRECTORY_SEPARATOR . 'helpers.php');

