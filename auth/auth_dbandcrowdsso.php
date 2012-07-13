<?php
/**
* Database & Crowd SSO auth plug-in for phpBB3
*
* @package login
* @copyright (c) 2012 Forumatic, LLC
* @license http://opensource.org/licenses/gpl-license.php GNU Public License
*
*/

/**
* @ignore
*/
if (!defined('IN_PHPBB'))
{
	exit;
}

if (!function_exists('login_db'))
{
	include($phpbb_root_path . 'includes/auth/auth_db.php');
}

function dbandcrowdsso_request($query, $method = 'GET', $request_body = '')
{
	global $config;
	$authcode = base64_encode($config['crowdsso_app_name'] . ":" . $config['crowdsso_password']);

	$opts = array(
		'http' => array(
			'method' => $method,
			'header' => array(
				'Accept' => 'application/json',
				'Content-type' => 'application/json',
				'Authorization' => 'Basic ' . $authcode,
			),
			'content' => $request_body,
		)
	);

	$context = stream_context_create($opts);

	if (false === ($response = @file_get_contents($config['crowdsso_url'] . $query, false, $context)))
	{
		throw new RuntimeException('Crowd SSO HTTP Request failed with: ' . error_get_last());
	}

	$response = @json_decode($response);

	if (!$response)
	{
		throw new RuntimeException('Crowd SSO HTTP Request failed to decode JSON response: ' . error_get_last());
	}

	return $response;
}

function dbandcrowdsso_get_token()
{
	global $config;

	static $cookie_name = null;

	if (null === $cookie_name) {
		$cookie_info = unserialize($config['crowdsso_cookie']);
		$cookie_name = $cookie_info['name'];
	}

	if (!isset($_COOKIE[$cookie_name]))
	{
		return false;
	}

	return $_COOKIE[$cookie_name];
}

function dbandcrowdsso_get_cookie_info()
{
	$query = 'rest/usermanagement/1/config/cookie';

	return dbandcrowdsso_request($query);
}

/**
* Connect to ldap server
* Only allow changing authentication to ldap if we can connect to the ldap server
* Called in acp_board while setting authentication plugins
*/
function init_dbandcrowdsso()
{
	global $config, $user;

	$query = 'rest/usermanagement/1/user?username=' . urlencode($user['username']);

	try
	{
		$user = dbandcrowdsso_request($query);
	}
	catch (RuntimeException $e)
	{
		return $e->getMessage();
	}

	$cookie_info = dbandcrowdsso_get_cookie_info();
	set_config('crowdsso_cookie', serialize($cookie_info));

	return false;
}

/**
* Login function
*
* @param string $username
* @param string $password
* @param string $ip			IP address the login is taking place from. Used to
*							limit the number of login attempts per IP address.
* @param string $browser	The user agent used to login
* @param string $forwarded_for X_FORWARDED_FOR header sent with login request
* @return array				A associative array of the format
*							array(
*								'status' => status constant
*								'error_msg' => string
*								'user_row' => array
*							)
*/
function login_dbandcrowdsso($username, $password, $ip = '', $browser = '', $forwarded_for = '')
{
	$result = login_db($username, $password, $ip, $browser, $forwarded_for);

	if ($result['status'] === LOGIN_SUCESS)
	{
		try
		{
			$user = $result['user_row'];

			$query = 'rest/usermanagement/1/session/' . rawurlencode($token) . '?validate-password=false';

			$request_body = array(
				'username' => $user['username'],
				'validationFactors' => array(
					'name' => 'remote_address',
					'value' => (string) $_SERVER['REMOTE_ADDR'],
				),
			);

			$session = dbandcrowdsso_request($query, 'POST', json_encode($request_body));

			return $result;
		}
		catch (RuntimeException $e)
		{
			// no login if error

			return array(
				'status' => LOGIN_ERROR_EXTERNAL_AUTH,
				'error_msg' => 'Failed to create crowd session: ' . $e->getMessage(),
				'user_row' => array('user_id' => ANONYMOUS),
			);
		}

		return array(
			'status' => LOGIN_ERROR_EXTERNAL_AUTH,
			'error_msg' => 'Failed to create crowd session with unknown error',
			'user_row' => array('user_id' => ANONYMOUS),
		);
	}

	return $result;
}

/**
* Autologin function
*
* @return array containing the user row or empty if no auto login should take place
*/
function autologin_dbandcrowdsso()
{
	global $db;

	$token = dbandcrowdsso_get_token();

	if (!$token)
	{
		return array();
	}

	try
	{
		$query = 'rest/usermanagement/1/session/' . rawurlencode($token);
		$session = dbandcrowdsso_request($query);

		if (isset($session['user']['name']))
		{
			$sql = 'SELECT *
				FROM ' . USERS_TABLE . "
				WHERE username_clean = '" . $db->sql_escape(utf8_clean_string($session['user']['name'])) . "'";
			$result = $db->sql_query($sql);
			$row = $db->sql_fetchrow($result);
			$db->sql_freeresult($result);

			if ($row)
			{
				return $row;
			}
		}
	}
	catch (RuntimeException $e)
	{
		// ignore - no autologin
	}

	return array();
}

/**
* The session validation function checks whether the user is still logged in
*
* @return boolean true if the given user is authenticated or false if the session should be closed
*/
function validate_session_dbandcrowdsso(&$user)
{
	$token = dbandcrowdsso_get_token();

	if ($token)
	{
		try
		{
			$query = 'rest/usermanagement/1/session/' . rawurlencode($token);

			$request_body = new stdclass;
			$request_body->validationFactors = array(
				array(
					'value' => (string) $_SERVER['REMOTE_ADDR'],
					'name' => 'remote_address',
				),
			);

			$session = dbandcrowdsso_request($query, 'POST', json_encode($request_body));

			// Check if PHP_AUTH_USER is set and handle this case
			if (isset($session['user']['name']))
			{
				return ($session['user']['name'] === $user['username']) ? true : false;
			}
		}
		catch (RuntimeException $e)
		{
			return false;
		}
	}

	// PHP_AUTH_USER is not set. A valid session is now determined by the user type (anonymous/bot or not)
	if ($user['user_type'] == USER_IGNORE)
	{
		return true;
	}

	return false;
}

/**
* This function is used to output any required fields in the authentication
* admin panel. It also defines any required configuration table fields.
*/
function acp_dbandcrowdsso(&$new)
{
	global $user, $config;

	if (!isset($config['crowdsso_cookie']))
	{
		set_config('crowdsso_cookie', '');
	}
	if (!isset($config['crowdsso_url']))
	{
		set_config('crowdsso_url', '');
	}
	if (!isset($config['crowdsso_app_name']))
	{
		set_config('crowdsso_app_name', '');
	}
	if (!isset($config['crowdsso_password']))
	{
		set_config('crowdsso_password', '');
	}

	$tpl = '

	<dl>
		<dt><label for="crowdsso_url">Crowd URL:</label><br /><span>The URL to your crowd instance, for example <em>http://crowd:8095/crowd/</em></span></dt>
		<dd><input type="text" id="crowdsso_url" size="40" name="config[crowdsso_url]" value="' . $new['crowdsso_url'] . '" /></dd>
	</dl>
	<dl>
		<dt><label for="crowdsso_app_name">Crowd App Name:</label><br /><span>Registered name of this application in your crowd server</span></dt>
		<dd><input type="text" id="crowdsso_app_name" size="40" name="config[crowdsso_app_name]" value="' . $new['crowdsso_app_name'] . '" /></dd>
	</dl>
	<dl>
		<dt><label for="crowdsso_password">Crowd Password:</label><br /><span>Please note the password will be stored in the phpBB database in plaintext.</span></dt>
		<dd><input type="password" id="crowdsso_password" size="40" name="config[crowdsso_password]" value="' . $new['crowdsso_password'] . '" autocomplete="off" /></dd>
	</dl>
	';

	// These are fields required in the config table
	return array(
		'tpl'		=> $tpl,
		'config'	=> array('crowdsso_url', 'crowdsso_app_name', 'crowdsso_password')
	);
}