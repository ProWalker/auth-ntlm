<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Authentication class for ntlm is defined here.
 *
 * @package     auth_ntlm
 * @copyright   2023 Nikita Maksimov <provoker.1986@gmail.com>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/authlib.php');
require_once($CFG->libdir . '/filestorage/file_exceptions.php');
require_once(__DIR__ . '/classes/exceptions/property_exception.php');

// For further information about authentication plugins please read
// https://docs.moodle.org/dev/Authentication_plugins.
//
// The base class auth_plugin_base is located at /lib/authlib.php.
// Override functions as needed.

/**
 * Authentication class for ntlm.
 */
class auth_plugin_ntlm extends auth_plugin_base {

    /**
     * Set the properties of the instance.
     */
    public function __construct() {
        $this->authtype = 'ntlm';
    }

    function loginpage_hook()
    {
        $sesskey = optional_param('sesskey', '', PARAM_TEXT);
        $current_ip = getenv("REMOTE_ADDR");
        $skipsso = optional_param('skipsso', false, PARAM_BOOL);

        if (isloggedin() and $skipsso) {
            require_logout();
        }

        if ($skipsso) {
            return false;
        }

        if (!$this->is_ip4_in_subnets($current_ip, $this->get_subnets())) {
            return false;
        }

        // Если в параметрах передан сессионный ключ, значит это попытка залогиниться автоматом
        if (!empty($sesskey)) {
            try {
                $this->login_user($sesskey);
            } catch (moodle_exception $e) {
                return true;
            }
        }

        if (!isloggedin()) {
            $sesskey = $this->get_unique_sesskey();

            $site_url = new moodle_url('/');
            $url = "https://sso.server.com:8891/?callback={$site_url->get_scheme()}://{$site_url->get_host()}/auth/ntlm/callback.php?sesskey={$sesskey}&backurl={$site_url->get_scheme()}://{$site_url->get_host()}/login/index.php?sesskey={$sesskey}";

            header('Location: ' . $url, true, 301);
            die();
        }
    }

    private function get_unique_sesskey()
    {
        $dir_path = __DIR__ . '/wantslogin/';

        while (true) {
            $sesskey = sesskey();

            if (!file_exists($dir_path . $sesskey . '.txt')) {
                break;
            }
        }

        return $sesskey;
    }

    public function postlogout_hook($user)
    {
        $url = new moodle_url('/login/index.php?skipsso=true');
        header('Location: ' . $url, true, 301);
    }

    /**
     * Функция логинит пользователя основываясь на его сессионном ключе
     *
     * @param $sesskey
     * @return void
     */
    function login_user($sesskey)
    {
        global $DB;

        $user_account_file = $this->get_user_account_file($sesskey);

        if (!$user_account_file) {
            throw new file_exception('filenotfound');
        }

        $user_login = $this->get_file_property($user_account_file, 'login');

        if ($user_login == 'not exists') {
            throw new property_exception('login');
        }

        $user = $DB->get_record('user', array('username' => $user_login)); // заменил на такую
        complete_user_login($user);
        unlink($user_account_file); // Файл нужен только для авторизации, поэтому избавляемся от него
        redirect(new moodle_url('/'));
    }

    /**
     * Check IPv4 address is within a range
     *
     * @param string $ip A valid IPv4 address (xxx.xxx.xxx.xxx)
     * @param string $subnet A valid IPv4 subnet (xxx.xxx.xxx.xxx)
     * @param string $mask A valid IPv4 subnet mask (a number from 0-32)
     * @return boolean True if the address is within the range, false if it isn't
     */
    function is_ip4_in_network($ip, $subnet, $mask) {
        if ($mask <= 0) {
            return false;
        }

        $ip_bin_string = sprintf("%032b", ip2long($ip));
        $net_bin_string = sprintf("%032b", ip2long($subnet));

        return (substr_compare($ip_bin_string, $net_bin_string, 0, $mask) === 0);
    }

    /**
     * Возвращаем список подсетей. В данный момент берём их из плагина ldap.
     *
     * @return array|array[]
     * @throws dml_exception
     */
    function get_subnets() {
        // Здесь мы получаем подсети в формате 192.168.0.0/24, 10.0.0.0/16
        $ldap_subnets = get_config('auth_ldap', 'ntlmsso_subnet');
        $ldap_subnets = explode(',', $ldap_subnets);
        $ldap_subnets = array_map(function ($cidr) {
            $cidr = trim($cidr);
            $cidr = explode('/', $cidr);
            $subnet_mask = $cidr[0];
            $subnet_prefix = $cidr[1];

            return array('subnet_mask' => $subnet_mask, 'subnet_prefix' => $subnet_prefix);
        }, $ldap_subnets);

        return $ldap_subnets;
    }

    /**
     * ip пользователя должен быть хотя бы в одной из указанных подсетей
     *
     * @param $user_ip string
     * @param $subnets array
     * @return bool
     * @throws dml_exception
     */
    function is_ip4_in_subnets($user_ip, $subnets) {
        foreach ($subnets as $subnet) {
            if ($this->is_ip4_in_network($user_ip, $subnet['subnet_mask'], $subnet['subnet_prefix'])) {
                return true;
            }
        }

        return false;
    }

    function get_user_account_file($userfilename) {
        $dir_path = __DIR__ . '/wantslogin/';

        $files = scandir($dir_path);

        foreach ($files as $file) {
            $filename = explode('.txt', $file)[0];

            if (strtolower($filename) == strtolower($userfilename)) {
                return $dir_path . $file;
            }
        }

        return false;
    }

    // Формат свойств файла: property1:value1;property2:value2;property3:value3
    function set_property_to_file($filename, $property, $value) {
        $file_content = file_get_contents($filename);

        if (empty($file_content)) {
            return false;
        }

        $file_properties = explode(';', $file_content);
        $property_exists = false;

        foreach ($file_properties as &$file_property) {
            list($prop_name) = explode(':', $file_property);

            if ($prop_name == $property) {
                $file_property = implode(':', array($prop_name, $value));
                $property_exists = true;
                break;
            }
        }

        if (!$property_exists) {
            $new_property = implode(':', array($property, $value));
            file_put_contents($filename, ';' . $new_property, FILE_APPEND);

            return true;
        }

        file_put_contents($filename, implode(';', $file_properties));

        return true;

    }

    // Формат свойств файла: property1:value1;property2:value2;property3:value3
    function get_file_property($filename, $property) {
        $file_content = file_get_contents($filename);

        if (empty($file_content)) {
            return 'not_exists';
        }

        $file_properties = explode(';', $file_content);

        foreach ($file_properties as $file_property) {
            list($prop_name, $prop_value) = explode(':', $file_property);

            if ($prop_name == $property) {
                return $prop_value;
            }
        }

        return 'not_exists';
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    public function is_internal() {
        return true;
    }

    /**
     * Returns whether or not this authentication plugin can be manually set
     * for users, for example, when bulk uploading users.
     *
     * This should be overriden by authentication plugins where setting the
     * authentication method manually is allowed.
     *
     * @return bool
     */
    public function can_be_manually_set() {
        return true;
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username.
     * @param string $password The password.
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password) {
        global $CFG, $DB;

        // Validate the login by using the Moodle user table.
        // Remove if a different authentication method is desired.
        $user = $DB->get_record('user', array('username' => $username, 'mnethostid' => $CFG->mnet_localhost_id));

        // User does not exist.
        if (!$user) {
            return false;
        }

        return true;
    }
}
