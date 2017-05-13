<?php

namespace fpoirotte\Cryptal;

function init()
{
    static $inited = false;

    if ($inited) {
        return;
    }

    stream_wrapper_register("cryptal.encrypt", "\\fpoirotte\Cryptal\\CryptoStream")
        or die("Failed to register 'cryptal.encrypt' stream wrapper");
    stream_wrapper_register("cryptal.decrypt", "\\fpoirotte\Cryptal\\CryptoStream")
        or die("Failed to register 'cryptal.decrypt' stream wrapper");

    $inited = true;
}
