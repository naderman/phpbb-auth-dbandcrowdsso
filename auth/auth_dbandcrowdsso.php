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
			'header' =>
				"Accept: application/json\r\n".
				"Content-Type: application/json\r\n".
				"Authorization: Basic $authcode\r\n",
			'follow_location' => false,
		)
	);

	if ($request_body)
	{
		$opts['http']['content'] = $request_body;
	}

	$context = stream_context_create($opts);

	$prev_error = error_get_last();

	$url = strpos($query, 'http://') === 0 ? $query : $config['crowdsso_url'] . $query;

	if (false === ($response = @file_get_contents($url, false, $context)))
	{
		if (!isset($http_response_header[0]) || $http_response_header[0] !== 'HTTP/1.1 201 Created')
		{
			$error = error_get_last();

			if ($error != $prev_error)
			{
				$message = $error['message'] . ' in file ' . $error['file'] . ' on line ' . $error['line'];
			}
			else
			{
				$message = 'Unknown (' . $http_response_header[0] . ')';
			}

			throw new RuntimeException('Crowd SSO HTTP Request failed with: ' . $message);
		}
	}

	$prev_error = error_get_last();

	foreach ($http_response_header as $header)
	{
		if (preg_match('/^\s*Location:\s*(\S+)$/', $header, $matches))
		{
			return dbandcrowdsso_request($matches[1]);
		}
	}

	if (!$response)
	{
		return $response;
	}

	$response = @json_decode($response);

	if (!$response)
	{
		$error = error_get_last();

		if ($error != $prev_error)
		{
			$message = $error['message'] . ' in file ' . $error['file'] . ' on line ' . $error['line'];
		}
		else
		{
			$message = 'Unknown';
		}

		throw new RuntimeException('Crowd SSO HTTP Request failed to decode JSON response: ' . $error['message'] . ' in file ' . $error['file'] . ' on line ' . $error['line']);
	}

	return $response;
}

function dbandcrowdsso_get_token()
{
	global $config;

	static $cookie_name = null;

	if (null === $cookie_name)
	{
		$cookie_info = unserialize($config['crowdsso_cookie']);
		$cookie_name = str_replace('.', '_', $cookie_info->name);
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

function dbandcrowdsso_setcookie($token, $expire = false)
{
	global $config;

	if (defined('CROWD_LOGOUT'))
	{
		return;
	}

	$cookie_info = unserialize($config['crowdsso_cookie']);

	if ($expire)
	{
		$token = '';
		$time = time() - 3600;
	}
	else
	{
		$time = 0;
	}

	setcookie($cookie_info->name, $token, $time, '/', $cookie_info->domain, $cookie_info->secure, true);

	if ($expire)
	{
		unset($_COOKIE[$cookie_info->name]);
	}
	else
	{
		$_COOKIE[$cookie_info->name] = $token;
	}
}

/**
* Connect to ldap server
* Only allow changing authentication to ldap if we can connect to the ldap server
* Called in acp_board while setting authentication plugins
*/
function init_dbandcrowdsso()
{
	global $config, $user;

	$query = 'rest/usermanagement/1/user?username=' . urlencode($user->data['username']);

	try
	{
		$admin_user = dbandcrowdsso_request($query);
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
	global $config;

	$result = login_db($username, $password, $ip, $browser, $forwarded_for);

	if ($result['status'] === LOGIN_SUCCESS)
	{
		$token = dbandcrowdsso_get_token();

		if ($token)
		{
			// assume token is correct, afterall authentication was successful
			// validate session will logout if they don't match anyway
			return $result;
		}

		try
		{
			$user = $result['user_row'];

			$query = 'rest/usermanagement/1/session?validate-password=false';

			$request_body = array(
				'username' => $user['username'],
				'password' => $password,
				'validation-factors' => array(
					'validationFactors' => array(
						array(
							'name' => 'remote_address',
							'value' => (string) $_SERVER['REMOTE_ADDR'],
						),
					),
				),
			);

			$session = dbandcrowdsso_request($query, 'POST', json_encode($request_body));

			dbandcrowdsso_setcookie($session->token);

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
	if (defined('CROWD_LOGOUT'))
	{
		return;
	}

	global $db, $config;

	$token = dbandcrowdsso_get_token();

	try
	{
		if ($token)
		{
			$query = 'rest/usermanagement/1/session/' . rawurlencode($token);
			$session = dbandcrowdsso_request($query);

			if (isset($session->user) && isset($session->user->name))
			{
				$sql = 'SELECT *
					FROM ' . USERS_TABLE . "
					WHERE username_clean = '" . $db->sql_escape(utf8_clean_string($session->user->name)) . "'";
				$result = $db->sql_query($sql);
				$row = $db->sql_fetchrow($result);
				$db->sql_freeresult($result);

				if ($row)
				{
					return $row;
				}
			}
		}
	}
	catch (RuntimeException $e)
	{
		// ignore - no autologin
	}

	$cookie_data            = array('u' => 0, 'k' => '');

	if (isset($_COOKIE[$config['cookie_name'] . '_sid']) || isset($_COOKIE[$config['cookie_name'] . '_u']))
	{
		$cookie_data['u'] = request_var($config['cookie_name'] . '_u', 0, false, true);
		$cookie_data['k'] = request_var($config['cookie_name'] . '_k', '', false, true);
	}

	if (!$config['allow_autologin'])
	{
		$cookie_data['k'] = false;
	}

	// if no phpbb autologin cookie is set, return an empty array -> new session
	// validate session takes care of deleting the crowd cookie if the autologin is invalid
	if (!$cookie_data['k'] || !$cookie_data['u'])
	{
		return array();
	}

	// else try to log the user into the sso system too
	try
	{
		$sql = 'SELECT *
			FROM ' . USERS_TABLE . "
			WHERE user_id = '" . (int) $cookie_data['u'] . "'";
		$result = $db->sql_query($sql);
		$user = $db->sql_fetchrow($result);
		$db->sql_freeresult($result);

		$query = 'rest/usermanagement/1/session?validate-password=false';

		$request_body = array(
			'username' => $user['username'],
			'password' => $password,
			'validation-factors' => array(
				'validationFactors' => array(
					array(
						'name' => 'remote_address',
						'value' => (string) $_SERVER['REMOTE_ADDR'],
					),
				),
			),
		);

		$session = dbandcrowdsso_request($query, 'POST', json_encode($request_body));

		dbandcrowdsso_setcookie($session->token);

		if (isset($session->user) && isset($session->user->name))
		{
			$sql = 'SELECT *
				FROM ' . USERS_TABLE . "
				WHERE username_clean = '" . $db->sql_escape(utf8_clean_string($session->user->name)) . "'";
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
	global $config;

	$token = dbandcrowdsso_get_token();

	if ($token)
	{
		// logout doesn't go to this API otherwise so need to use some trickery
		if (preg_match('#\/ucp\.php\?mode=logout#', $_SERVER['REQUEST_URI']))
		{
			$query = 'rest/usermanagement/1/session/' . rawurlencode($token);
			dbandcrowdsso_request($query, 'DELETE');

			dbandcrowdsso_setcookie('', true);

			define('CROWD_LOGOUT', true);
			return true;
		}

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
			if (isset($session->user) && isset($session->user->name))
			{
				if ($session->user->name === $user['username'])
				{
					return true;
				}
				else
				{
					return false;
				}
			}
		}
		catch (RuntimeException $e)
		{
			dbandcrowdsso_setcookie('', true);
			return false;
		}
	}

	// PHP_AUTH_USER is not set. A valid session is now determined by the user type (anonymous/bot or not)
	if ($user['user_type'] == USER_IGNORE)
	{
		return true;
	}

	dbandcrowdsso_setcookie('', true);

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
