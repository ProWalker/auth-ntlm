<?php

require_once(__DIR__ . '/../../config.php');

global $DB;

$sesskey = optional_param('sesskey', '', PARAM_TEXT);

if (!empty($_REQUEST['ticket'])) {
    $login = explode('@', $_REQUEST['login'])[0];

    if (file_exists(__DIR__ . "/wantslogin/{$sesskey}.txt")) {
        throw new file_exception('fileexists');
    }

    file_put_contents(__DIR__ . "/wantslogin/{$sesskey}.txt", "login:{$login}");
}