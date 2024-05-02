<?php

require_once(__DIR__ . '/../../config.php');

//redirect(new moodle_url('/', array('sso' => 1)));

//die(1111);

$url = "/?sso=1";
header('Location: ' . $url, true, 301);