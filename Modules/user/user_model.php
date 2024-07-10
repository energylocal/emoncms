<?php
/*
   All Emoncms code is released under the GNU Affero General Public License.
   See COPYRIGHT.txt and LICENSE.txt.

   ---------------------------------------------------------------------
   Emoncms - open source energy visualisation
   Part of the OpenEnergyMonitor project:
   http://openenergymonitor.org
*/

// no direct access
defined('EMONCMS_EXEC') or die('Restricted access');

class User
{
    private $mysqli;
    private $rememberme;
    private $enable_rememberme = false;
    private $email_verification = false;
    private $redis;
    private $log;
    public $appname;

    public function __construct($mysqli,$redis)
    {
        //copy the settings value, otherwise the enable_rememberme will always be false.
        global $settings;
        $this->enable_rememberme = $settings["interface"]["enable_rememberme"];
        $this->email_verification = $settings["interface"]["email_verification"];
        $this->appname = $settings["interface"]["appname"];

        $this->mysqli = $mysqli;

        require "Modules/user/rememberme_model.php";
        $this->rememberme = new Rememberme($mysqli);

        $this->redis = $redis;
        $this->log = new EmonLogger(__FILE__);
    }

    //---------------------------------------------------------------------------------------
    // Core session methods
    //---------------------------------------------------------------------------------------

    public function apikey_session($apikey_in)
    {
        $session = array();
        
        // 1. Only allow alphanumeric characters
        // if (!ctype_alnum($apikey_in)) return $session;
        
        // 2. Only allow 32 character length
        if (strlen($apikey_in)!=32) return array();

        //----------------------------------------------------
        // Check redis cache first
        //----------------------------------------------------
        /*
        if($this->redis)
        {
            if ($this->redis->exists("writeapikey:$apikey_in")) {
                $session['userid'] = $this->redis->get("writeapikey:$apikey_in");
                $session['read'] = 1;
                $session['write'] = 1;
                $session['admin'] = 0;
                $session['lang'] = "en";      // API access is always in english
                $session['username'] = "API"; // TBD
                $session['gravatar'] = '';
                $session['public_userid'] = 0;
                $session['public_username'] = "";
                return $session;
            }
            
            if ($this->redis->exists("readapikey:$apikey_in")) {
                $session['userid'] = $this->redis->get("readapikey:$apikey_in");
                $session['read'] = 1;
                $session['write'] = 0;
                $session['admin'] = 0;
                $session['lang'] = "en";      // API access is always in english
                $session['username'] = "API"; // TBD
                $session['gravatar'] = '';
                $session['public_userid'] = 0;
                $session['public_username'] = "";
                return $session;
            }
        }*/
        
        //----------------------------------------------------
        // If not in redis check mysql
        //----------------------------------------------------
        $stmt = $this->mysqli->prepare("SELECT id,username FROM users WHERE apikey_write=?");
        $stmt->bind_param("s",$apikey_in);
        $stmt->execute();
        $stmt->bind_result($id,$username);
        $result = $stmt->fetch();
        $stmt->close();

        if ($result && $id>0) {
            $session['userid'] = $id;
            $session['read'] = 1;
            $session['write'] = 1;
            $session['admin'] = 0;
            $session['lang'] = "en"; // API access is always in english
            $session['username'] = $username;
            $session['gravatar'] = '';
            $session['public_userid'] = 0;
            $session['public_username'] = "";     
            if ($this->redis) $this->redis->set("writeapikey:$apikey_in",$id);
            return $session;
        }

        $stmt = $this->mysqli->prepare("SELECT id,username FROM users WHERE apikey_read=?");
        $stmt->bind_param("s",$apikey_in);
        $stmt->execute();
        $stmt->bind_result($id,$username);
        $result = $stmt->fetch();
        $stmt->close();
        
        if ($result && $id>0) {
            $session['userid'] = $id;
            $session['read'] = 1;
            $session['write'] = 0;
            $session['admin'] = 0;
            $session['lang'] = "en"; // API access is always in english
            $session['username'] = $username;
            $session['gravatar'] = '';
            $session['public_userid'] = 0;
            $session['public_username'] = "";       
            if ($this->redis) $this->redis->set("readapikey:$apikey_in",$id);
            return $session;
        }
        
        return array();
    }
    
    public function get_id_from_apikey($apikey_in) 
    {
        if (strlen($apikey_in)!=32) return false;
        // if (!ctype_alnum($apikey_in)) return false;
        
        $stmt = $this->mysqli->prepare("SELECT id FROM users WHERE apikey_read=? OR apikey_write=?");
        $stmt->bind_param("ss",$apikey_in,$apikey_in);
        $stmt->execute();
        $stmt->bind_result($id);
        $stmt->fetch();
        $stmt->close();
        return $id;
    }

    public function emon_session_start()
    {
        // useful for testing session and rememberme
        // ini_set('session.gc_maxlifetime', 20);
        // session_set_cookie_params(20);
        
        $cookie_params = session_get_cookie_params();

        //name of cookie 
        session_name('EMONCMS_SESSID'); 
        //get subdir installation 
        $cookie_params['path'] = dirname($_SERVER['SCRIPT_NAME']);
        // Add a slash if the last character isn't already a slash
        if (substr($cookie_params['path'], -1) !== '/')
            $cookie_params['path'] .= '/';
        //not pass cookie to javascript 
        $cookie_params['httponly'] = true;
        $cookie_params['samesite'] = 'Strict';
        
        if (is_https()) {
            $cookie_params['secure'] = true;
        }
        
        if (PHP_VERSION_ID>=70300) {
            session_set_cookie_params($cookie_params);
        } else {
            session_set_cookie_params(
                $cookie_params['lifetime'],
                $cookie_params['path'],
                $cookie_params['domain'],
                $cookie_params['secure'],
                $cookie_params['httponly']
            );
        }
        
        session_start();

        if ($this->enable_rememberme)
        {
            if (!empty($_SESSION['userid'])) {
                // if rememberme emoncms cookie exists but is not valid then
                // a valid cookie is a cookie who's userid, token and persistant token match a record in the db
                
                if ((isset($_SESSION['cookielogin']) && $_SESSION['cookielogin']==true) && !$this->rememberme->cookieIsValid($_SESSION['userid'])) {
                    $this->logout();
                }
            } else {
                // No session exists, try remember me login
                $loginresult = $this->rememberme->login();
                if ($loginresult)
                {
                    // 28/04/17: Changed explicitly stated fields to load all with * in order to access startingpage
                    // without cuasing an error if it has not yet been created in the database.
                    // SELECT id,username,admin,language,startingpage FROM users WHERE id = '$loginresult'
                    $loginresult = (int) $loginresult;
                    $result = $this->mysqli->query("SELECT * FROM users WHERE id = '$loginresult'");
                    if ($result->num_rows < 1) {
                        $this->logout(); // user id does not exist
                    } else {
                        $userData = $result->fetch_object();
                        if ($userData->id != 0)
                        {
                            $_SESSION['userid'] = $userData->id;
                            $_SESSION['username'] = $userData->username;
                            $_SESSION['read'] = 1;
                            $_SESSION['write'] = 1;
                            $_SESSION['admin'] = $userData->admin;
                            $_SESSION['lang'] = $userData->language;
                            $_SESSION['timezone'] = $userData->timezone;
                            if (isset($userData->startingpage)) $_SESSION['startingpage'] = $userData->startingpage;
                            // There is a chance that an attacker has stolen the login token, so we store
                            // the fact that the user was logged in via RememberMe (instead of login form)
                            $_SESSION['cookielogin'] = true;
                        }
                    }
                } else {
                    // if($this->rememberme->loginTokenWasInvalid()) {
                    //    $this->logout(); // Stolen
                    // }
                }
            }
        }
        
        if (isset($_SESSION['admin'])) $session['admin'] = $_SESSION['admin']; else $session['admin'] = 0;
        if (isset($_SESSION['read'])) $session['read'] = $_SESSION['read']; else $session['read'] = 0;
        if (isset($_SESSION['write'])) $session['write'] = $_SESSION['write']; else $session['write'] = 0;
        if (isset($_SESSION['userid'])) $session['userid'] = $_SESSION['userid']; else $session['userid'] = 0;
        if (isset($_SESSION['lang'])) $session['lang'] = $_SESSION['lang']; else $session['lang'] = 'cy_GB';
        if (isset($_SESSION['timezone'])) $session['timezone'] = $_SESSION['timezone']; else $session['timezone'] = '';
        if (isset($_SESSION['startingpage'])) $session['startingpage'] = $_SESSION['startingpage']; else $session['startingpage'] = '';
        if (isset($_SESSION['gravatar'])) $session['gravatar'] = $_SESSION['gravatar']; else $session['gravatar'] = '';
        if (isset($_SESSION['username'])) $session['username'] = $_SESSION['username']; else $session['username'] = 'REMEMBER_ME';
        if (isset($_SESSION['password'])) $session['password'] = $_SESSION['password']; else $session['password'] = 'REMEMBER_ME';
        if (isset($_SESSION['cookielogin'])) $session['cookielogin'] = $_SESSION['cookielogin']; else $session['cookielogin'] = 0;
        if (isset($_SESSION['emailverified'])) $session['emailverified'] = $_SESSION['emailverified'];

        $session['public_userid'] = 0;
        $session['public_username'] = "";

        return $session;
    }


    public function register($username, $password, $email, $timezone)
    {
        // Input validation, sanitisation and error reporting
        if (!$username || !$password || !$email) return array('success'=>false, 'message'=>_("Missing username, password or email parameter"));
        if (!ctype_alnum($username)) return array('success'=>false, 'message'=>_("Username must only contain a-z and 0-9 characters"));
        if ($this->get_id($username) != 0) return array('success'=>false, 'message'=>_("Username already exists"));

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return array('success'=>false, 'message'=>_("Email address format error"));

        if (strlen($username) < 3 || strlen($username) > 30) return array('success'=>false, 'message'=>_("Username length error"));
        if (strlen($password) < 4 || strlen($password) > 250) return array('success'=>false, 'message'=>_("Password length error"));
        
        if (!$this->timezone_valid($timezone)) {
            // use default UTC timezone if timezone is not valid
            $timezone = "UTC";
        }

        // If we got here the username, password and email should all be valid

        $hash = hash('sha256', $password);
        $salt = generate_secure_key(16);
        $password = hash('sha256', $salt . $hash);

        $apikey_write = generate_secure_key(16);
        $apikey_read = generate_secure_key(16);

        $stmt = $this->mysqli->prepare("INSERT INTO users ( username, password, email, salt ,apikey_read, apikey_write, timezone, admin) VALUES (?,?,?,?,?,?,?,0)");
        $stmt->bind_param("sssssss", $username, $password, $email, $salt, $apikey_read, $apikey_write, $timezone);
        if (!$stmt->execute()) {
            $error = $this->mysqli->error;
            $stmt->close();
            return array('success'=>false, 'message'=>_("Error creating user, mysql error: ".$error));
        }

        // Make the first user an admin
        $userid = $this->mysqli->insert_id;
        if ($userid == 1) $this->mysqli->query("UPDATE users SET admin = 1 WHERE id = '1'");
        $stmt->close();
        
        // Email verification
        if ($this->email_verification) {
            $result = $this->send_verification_email($username);
            if ($result['success']) return array('success'=>true, 'verifyemail'=>true, 'message'=>"Email verification email sent, please check your inbox");
        } else {
            return array('success'=>true, 'verifyemail'=>false, 'userid'=>$userid, 'apikey_read'=>$apikey_read, 'apikey_write'=>$apikey_write);
        }        
    }
    
    public function send_verification_email($username)
    {
        // check for valid username format
        if (preg_replace('/[^\p{N}\p{L}_\s\-]/u','',$username)!=$username) return array('success'=>false, 'message'=>_("Invalid username"));

        // check that username exists and load email and verification status
        if (!$stmt = $this->mysqli->prepare("SELECT id,email,email_verified FROM users WHERE username=?")) {
            return array('success'=>false, 'message'=>_("Database error, you may need to run database update"));
        }
        $stmt->bind_param("s",$username);
        $stmt->execute();
        
        $stmt->bind_result($id,$email,$email_verified);
        $result = $stmt->fetch();
        $stmt->close();
        
        // exit if user does not exist
        if (!$result || $id<1) return array('success'=>false, 'message'=>_("Username does not exist"));
        // exit if account is already verified
        if ($email_verified) return array('success'=>false, 'message'=>_("Email already verified"));
        
        // Create new verification key
        $verification_key = generate_secure_key(32);
        // Save new verification key
        $stmt = $this->mysqli->prepare("UPDATE users SET verification_key=? WHERE id=?");
        $stmt->bind_param("si",$verification_key,$id);
        $stmt->execute();
        $stmt->close();
        
        // Send verification email
        global $path;
        $verification_link = $path."user/verify?email=".urlencode($email)."&key=$verification_key";
        
        // $this->redis->rpush("emailqueue",json_encode(array(
        //    "emailto"=>$email,
        //    "type"=>"passwordrecovery",
        //    "subject"=>'Emoncms email verification',
        //    "message"=>"<p>To complete emoncms registration please verify your email by following this link: <a href='$verification_link'>$verification_link</a></p>"
        // )));
        
        require "Lib/email.php";
        $emailer = new Email();
        $emailer->to(array($email));
        $emailer->subject(ucfirst($this->appname).' email verification');
        $emailer->body("<p>To complete ".$this->appname." registration please verify your email by following this link: <a href='$verification_link'>$verification_link</a></p>");
        $result = $emailer->send();
        if (!$result['success']) {
            $this->log->error("Email send returned error. emailto=" . $email . " message='" . $result['message'] . "'");
        } else {
            $this->log->info("Email sent to $email");
        }
        
        return array('success'=>true, 'message'=>_("Email verification email sent, please check your inbox"));
    }
    
    public function verify_email($email,$verification_key)
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return array('success'=>false, 'message'=>_("Email address format error"));
        if (strlen($verification_key)!=64) return array('success'=>false, 'message'=>_("Invalid verification key"));
        
        $stmt = $this->mysqli->prepare("SELECT id,email_verified FROM users WHERE email=? AND verification_key=?");
        $stmt->bind_param("ss",$email,$verification_key);
        $stmt->execute();
        $stmt->bind_result($id,$email_verified);
        $result = $stmt->fetch();
        $stmt->close();
        
        if ($result && $id>0) {
            if ($email_verified==0) {
                $stmt = $this->mysqli->prepare("UPDATE users SET email_verified='1' WHERE id=?");
                $stmt->bind_param("i",$id);
                $stmt->execute();
                $stmt->close();
                return array('success'=>true, 'message'=>"Email verified");
            } else {
                return array('success'=>false, 'message'=>"Email already verified");
            }
        }
        
        return array('success'=>false, 'message'=>"Invalid email or verification key");
    }

    public function login($username_or_email, $password, $remembermecheck, $referrer='')
    {
        $remembermecheck = (int) $remembermecheck;

        if (!$username_or_email || !$password) return array('success'=>false, 'message'=>_("Username or password empty"));

        if (!$stmt = $this->mysqli->prepare("SELECT id FROM users WHERE username=? OR email=?")) {
            return array('success'=>false, 'message'=>_("Database error, you may need to run database update"));
        }
        $stmt->bind_param("ss",$username_or_email,$username_or_email);
        $stmt->execute();
        $stmt->bind_result($userid);
        $result = $stmt->fetch();
        $stmt->close();
        
        if (!$userid) {
            $this->log->error("Login: Username does not exist username:$username_or_email ip:".get_client_ip_env());
            return array('success'=>false, 'message'=>_("Username does not exist"));
        }
        
        $result = $this->mysqli->query("SELECT * FROM users WHERE id = '$userid'");
        if (!$result) return array('success'=>false, 'message'=>_("Database error"));
        
        $userData = $result->fetch_object();
        
        if ($this->email_verification && isset($userData->email_verified) && !$userData->email_verified) return array('success'=>false, 'message'=>_("Please verify email address"));
        
        $hash = hash('sha256', $userData->salt . hash('sha256', $password));

        if ($hash != $userData->password)
        {
            $this->log->error("Login: Incorrect password username:$username_or_email ip:".get_client_ip_env());
            return array('success'=>false, 'message'=>_("Incorrect password"));
        }
        else
        {
            //--------------------------------------------------------------------
            include "Modules/remoteaccess/remoteaccess_userlink.php";
            $result = remoteaccess_userlink_existing($this->mysqli,$userid);
            if (!isset($result["success"]) || !$result["success"]) return $result;
            //--------------------------------------------------------------------
            
            session_regenerate_id();
            $_SESSION['userid'] = $userData->id;
            $_SESSION['username'] = $userData->username;
            $_SESSION['password'] = $password;
            $_SESSION['read'] = 1;
            $_SESSION['write'] = 1;
            $_SESSION['admin'] = $userData->admin;
            $_SESSION['lang'] = $userData->language;
            $_SESSION['timezone'] = $userData->timezone;
            $_SESSION['startingpage'] = $userData->startingpage;
            $_SESSION['gravatar'] = $userData->gravatar;
                                        
            if ($this->enable_rememberme) {
                if ($remembermecheck==true) {
                    if (!$this->rememberme->createCookie($userData->id)) {
                        $this->logout();
                        return array('success'=>false, 'message'=>_("Error creating rememberme cookie, try login without rememberme"));
                    }
                } else {
                    $this->rememberme->clearCookie();
                }
            }
            
            if ($this->redis) $this->redis->hmset("user:".$userData->id,array('apikey_write'=>$userData->apikey_write));

            if(!empty($referrer)) $userData->startingpage = urldecode($referrer);
            $stmt = $this->mysqli->prepare("UPDATE users SET lastlogin = CURRENT_TIMESTAMP WHERE id=?");
            $stmt->bind_param("i",$userid);
            $stmt->execute();
            $stmt->close();
            return array('success'=>true, 'message'=>_("Login successful"), 'startingpage'=>$userData->startingpage);
        }
    }

    // Authorization API. returns user write and read apikey on correct username + password
    // This is useful for using emoncms with 3rd party applications

    public function get_apikeys_from_login($username_or_email, $password)
    {
        if (!$username_or_email || !$password) return array('success'=>false, 'message'=>_("Username or password empty"));
        // $username_out = preg_replace('/[^\p{N}\p{L}_\s\-]/u','',$username);
        // if ($username_out!=$username) return array('success'=>false, 'message'=>_("Username must only contain a-z 0-9 dash and underscore"));

        $stmt = $this->mysqli->prepare("SELECT id,password,salt,apikey_write,apikey_read FROM users WHERE username=? OR email=?");
        $stmt->bind_param("ss",$username_or_email,$username_or_email);
        $stmt->execute();
        //$result = $stmt->get_result();
        //$userData = $result->fetch_object();
        //$stmt->close();
        
        $stmt->bind_result($userData_id,$userData_password,$userData_salt,$userData_apikey_write,$userData_apikey_read);
        $result = $stmt->fetch();
        $stmt->close();
        
        if (!$result) {
            $ip_address = get_client_ip_env();
            $this->log->error("get_apikeys_from_login: Incorrect authentication:$username ip:$ip_address");
            return array('success'=>false, 'message'=>_("Incorrect authentication"));
        }
       
        $hash = hash('sha256', $userData_salt . hash('sha256', $password));

        if ($hash != $userData_password) {
            return array('success'=>false, 'message'=>_("Incorrect authentication"));
        } else {
            return array('success'=>true, 'userid'=>$userData_id, 'apikey_write'=>$userData_apikey_write, 'apikey_read'=>$userData_apikey_read);
        }
    }

    public function logout()
    {
        $this->log->info("logout");
        if ($this->enable_rememberme) $this->rememberme->clearCookie();
        session_unset();
        //session_regenerate_id(true);
        session_destroy();
    }

    public function change_password($userid, $old, $new)
    {
        $userid = (int) $userid;

        if (strlen($old) < 4 || strlen($old) > 250) return array('success'=>false, 'message'=>_("Password length error"));
        if (strlen($new) < 4 || strlen($new) > 250) return array('success'=>false, 'message'=>_("Password length error"));

        // 1) check that old password is correct
        $result = $this->mysqli->query("SELECT password, salt FROM users WHERE id = '$userid'");
        $row = $result->fetch_object();
        $hash = hash('sha256', $row->salt . hash('sha256', $old));

        if ($hash == $row->password)
        {
            // 2) Save new password
            $hash = hash('sha256', $new);
            $salt = generate_secure_key(16);
            $password = hash('sha256', $salt . $hash);

            $stmt = $this->mysqli->prepare("UPDATE users SET password = ?, salt = ? WHERE id = ?");
            $stmt->bind_param("ssi", $password, $salt, $userid);
            $stmt->execute();
            $stmt->close();
            
            return array('success'=>true, 'message'=>_("Password updated successfully"));
        }
        else
        {
            $ip_address = get_client_ip_env();
            $this->log->error("change_password: old password incorect ip:$ip_address");
            return array('success'=>false, 'message'=>_("Old password incorect"));
        }
    }

    public function passwordreset_generation($username, $emailto, $base_url) {
        // cleaning up expired tokens from database
        $stmt = $this->mysqli->prepare("DELETE FROM password_reset_tokens WHERE expiry_time < NOW()");
        $stmt->execute();
        $stmt->close();
        
        if (is_array($username)) {
            if ($username['user_not_found']) {
                return array('success'=>false, 'message'=>"Invalid username or email.", 'reset_disabled'=>false, 'invalid_user_email'=>true);
            }
        }
        // sanitize username
        $username_out = preg_replace('/[^\p{N}\p{L}_\s\-]/u','',$username);
        // validate email format
        if (!filter_var($emailto, FILTER_VALIDATE_EMAIL)) return array('success'=>false, 'message'=>_("Email address format error"));

        // check that there is a match for username + email
        $stmt = $this->mysqli->prepare("SELECT id FROM users WHERE username=? AND email=?");
        $stmt->bind_param("ss",$username_out,$emailto);
        $stmt->execute();
        $stmt->bind_result($userid);
        $stmt->fetch();
        $stmt->close();
        
        // check that password reset is enabled
        global $settings;
        if (!$settings["interface"]["enable_password_reset"]) {
            return array('success'=>false, 'message'=>"Password reset disabled.", 'reset_disabled'=>true, 'invalid_user_email'=>false);
        }


        // base URL for password reset
        $base_url = $base_url . "&reset=";
        // generate random token
        $token = hash('sha256',generate_secure_key(32));
        
        // send email with reset link to $emailto
        require "Lib/email.php";
        $email = new Email();
        $email->to($emailto);
        $email->subject(ucfirst($this->appname).' password reset');
        $email->body("<p>A password reset was requested for your ".$this->appname." account.</p><p>You can now set a new password at the following link: " . $base_url . $token . "</p>");
        $result = $email->send();
        if (!$result['success']) {
            $this->log->error("Email send returned error. emailto=" . $emailto . " message='" . $result['message'] . "'");
            return array('success'=>false, 'message'=>$result['message']);
        } 

        $this->log->info("Email sent to $emailto");
        // add user id, token and token expiry time to database
        $stmt = $this->mysqli->prepare("INSERT INTO password_reset_tokens (userid, token, expiry_time) VALUES (?, ?, NOW() + INTERVAL 1 HOUR)");
        $stmt->bind_param("is",$userid,$token);
        $stmt->execute();
        $stmt->close();
        return array('success'=>true, 'message'=>"Password recovery email sent!", 'reset_disabled'=>false, 'invalid_user_email'=>false);          

    }

    public function passwordreset_check_token($token) {
        // check that the token is valid and has not expired
        $stmt = $this->mysqli->prepare("SELECT userid, (expiry_time > NOW()) AS valid FROM password_reset_tokens WHERE token=?");
        $stmt->bind_param("s",$token);
        $stmt->execute();
        $stmt->bind_result($userid, $token_validity);
        $stmt->fetch(); 
        // if token is valid, return user id
        if ($userid!==false && $userid>0 && $token_validity == 1) {
            $stmt->close();
            return array('success'=>true, 'user_id'=>$userid, 'message'=>"Token found!", 'token_exists'=>true, 'token_expired'=>false);
        // if token is not found, repeat search without checking expiry time to see if the token has expired
        } 
        if ($userid!==false && $userid>0 && $token_validity == 0) {
            $stmt->close();
            return array('success'=>false, 'message'=>"Token expired!", 'token_exists'=>true, 'token_expired'=>true);
        }
            // if token still isn't found, it was never a valid token
        $stmt->close();
        return array('success'=>false, 'message'=>"Token not found for this user!", 'token_exists'=>false, 'token_expired'=>false);
    }

    public function passwordreset_reset($token, $new_password) {
        // check again that the token is valid and has not expired
        $stmt = $this->mysqli->prepare("SELECT userid FROM password_reset_tokens WHERE token=? AND expiry_time > NOW()");
        $stmt->bind_param("s",$token);
        $stmt->execute();
        $stmt->bind_result($user_id);
        $stmt->fetch();
        $stmt->close();
        // if token is valid
        if ($user_id!==false && $user_id>0) {
            // generating hash/salt/password from supplied new password
            $hash = hash('sha256', $new_password);
            $salt = generate_secure_key(16);
            $password = hash('sha256', $salt . $hash);
            
            // checking that their current password is not the same as their new password
            $stmt = $this->mysqli->prepare("SELECT salt FROM users WHERE id=?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->bind_result($old_salt);
            $stmt->fetch();
            $stmt->close();
            // use old salt with new password to check that old password isn't being reused
            $password_check = hash('sha256', $old_salt . $hash);
            $stmt = $this->mysqli->prepare("SELECT id FROM users WHERE id=? AND password=?");
            $stmt->bind_param("is", $user_id, $password_check);
            $stmt->execute();
            $stmt->bind_result($duplicate_check);
            $stmt->fetch();
            // if their new password is the same as their current password, send a message back to the frontend so that the user can try again
            if ($duplicate_check!==false && $duplicate_check>0) {
                return array('success'=>false, 'message'=>"Duplicate password!", 'duplicate'=>true);
            } else {
                // change password and salt for specified user
                $stmt = $this->mysqli->prepare("UPDATE users SET password = ?, salt = ? WHERE id = ?");
                $stmt->bind_param("ssi", $password, $salt, $user_id);
                $stmt->execute();
                $stmt->close();
                // delete the now used reset token
                $stmt = $this->mysqli->prepare("DELETE FROM password_reset_tokens WHERE token = ?");
                $stmt->bind_param("s", $token);
                $stmt->execute();
                $stmt->close();
                return array('success'=>true, 'message'=>"Password changed!");
            }   

        } else {
            return array('success'=>false, 'message'=>"Token not found!", 'duplicate'=>false);
        }
    }
    

    public function change_username($userid, $username)
    {
        if (isset($_SESSION['cookielogin']) && $_SESSION['cookielogin']==true) return array('success'=>false, 'message'=>_("As you are using a cookie based remember me login, please logout and log back in to change username"));

        $userid = (int) $userid;
        if (strlen($username) < 3 || strlen($username) > 30) return array('success'=>false, 'message'=>_("Username length error"));

        if (!ctype_alnum($username)) return array('success'=>false, 'message'=>_("Username must only contain a-z and 0-9 characters"));

        $userid_from_username = $this->get_id($username);

        if (!$userid_from_username)
        {
            $stmt = $this->mysqli->prepare("UPDATE users SET username = ? WHERE id = ?");
            $stmt->bind_param("si", $username, $userid);
            $stmt->execute();
            $stmt->close();
            return array('success'=>true, 'message'=>_("Username updated"));
        }
        else
        {
            return array('success'=>false, 'message'=>_("Username already exists"));
        }
    }

    public function change_email($userid, $email)
    {
        if (isset($_SESSION['cookielogin']) && $_SESSION['cookielogin']==true) return array('success'=>false, 'message'=>_("As you are using a cookie based remember me login, please logout and log back in to change email"));

        $userid = (int) $userid;
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return array('success'=>false, 'message'=>_("Email address format error"));

        $stmt = $this->mysqli->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->bind_param("si", $email, $userid);
        $stmt->execute();
        $stmt->close();

        // $stmt = $this->mysqli->prepare("UPDATE users SET email_verified='0' WHERE id = ?");
        // $stmt->bind_param("i", $userid);
        // $stmt->execute();
        // $stmt->close();
        
        // global $session;
        // $session['emailverified'] = 0;
        // $_SESSION['emailverified'] = 0;
        
        return array('success'=>true, 'message'=>_("Email updated"));
    }

    //---------------------------------------------------------------------------------------
    // Get by userid methods
    //---------------------------------------------------------------------------------------
    public function get_username($userid)
    {
        $userid = (int) $userid;
        $result = $this->mysqli->query("SELECT username FROM users WHERE id = '$userid';");
        $row = $result->fetch_array();
        return $row['username'];
    }

    public function get_name($userid)
    {
        $userid = (int) $userid;
        $result = $this->mysqli->query("SELECT name FROM users WHERE id = '$userid';");
        $row = $result->fetch_array();
        return $row['name'];
    }

    public function get_email($userid)
    {
        $userid = (int) $userid;
        $result = $this->mysqli->query("SELECT email FROM users WHERE id = '$userid';");
        $row = $result->fetch_array();
        return $row['email'];
    }

    public function get_apikey_read($userid)
    {
        $userid = (int) $userid;
        $result = $this->mysqli->query("SELECT `apikey_read` FROM users WHERE `id`='$userid'");
        if (!$row = $result->fetch_object()) return false;
        return $row->apikey_read;
    }

    public function get_apikey_write($userid)
    {
        $userid = (int) $userid;
        $result = $this->mysqli->query("SELECT `apikey_write` FROM users WHERE `id`='$userid'");
        if (!$row = $result->fetch_object()) return false;
        return $row->apikey_write;
    }

    public function get_lang($userid)
    {
        $userid = (int) $userid;
        $result = $this->mysqli->query("SELECT language FROM users WHERE id = '$userid';");
        $row = $result->fetch_array();
        return $row['language'];
    }

    public function get_timezone_offset($userid)
    {
        $userid = (int) $userid;
        if (!$userid) return false;
        $result = $this->mysqli->query("SELECT timezone FROM users WHERE id = '$userid';");
        $row = $result->fetch_object();
        $now = new DateTime();
        $now->setTimezone(new DateTimeZone($row->timezone));
        return intval($now->getOffset()); // Will return seconds offset from GMT
    }

    public function get_timezone($userid)
    {
        $userid = (int) $userid;
        if (!$userid) return false;
        if ($result = $this->mysqli->query("SELECT timezone FROM users WHERE id = '$userid';")) {
            if ($row = $result->fetch_object()) {
                return $row->timezone;
            }
        }
        return false;
    }

    // List supported PHP timezones
    public function get_timezones()
    {
        static $timezones = null;

        if ($timezones === null) {
            $timezones = array();
            $now = new DateTime();

            foreach (DateTimeZone::listIdentifiers() as $timezone) {
                $now->setTimezone(new DateTimeZone($timezone));
                $offset = $now->getOffset();
                $hours = intval($offset / 3600);
                $minutes = abs(intval($offset % 3600 / 60));
                $gmt_offset_text = 'GMT ' . ($offset ? sprintf('%+03d:%02d', $hours, $minutes) : '+00:00');
                $timezones[] =  array('id'=>$timezone, 'gmt_offset_secs'=>$offset, 'gmt_offset_text'=>$gmt_offset_text);
            }
        }
        return $timezones;
    }
    
    public function timezone_valid($_timezone) 
    {
        foreach (DateTimeZone::listIdentifiers() as $timezone) {
            if ($timezone==$_timezone) return true;
        }
        return false;
    }

    public function get_salt($userid)
    {
        $userid = (int) $userid;
        $result = $this->mysqli->query("SELECT salt FROM users WHERE id = '$userid'");
        $row = $result->fetch_object();
        return $row->salt;
    }

    //---------------------------------------------------------------------------------------
    // Get by other paramater methods
    //---------------------------------------------------------------------------------------
    public function get_id($username)
    {   
        if (!ctype_alnum($username)) return 0;
        
        if (!$stmt = $this->mysqli->prepare("SELECT id FROM users WHERE username = ?")) {
            return 0;
        }
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($id);
        if (!$stmt->fetch()) {
            $stmt->close();
            return 0;
        } else {
            $stmt->close();
            return $id;
        }
    }

    //---------------------------------------------------------------------------------------
    // Set by id methods
    //---------------------------------------------------------------------------------------
    public function set_user_lang($userid, $lang)
    {   
        $stmt = $this->mysqli->prepare("UPDATE users SET language = ? WHERE id = ?");
        $stmt->bind_param("si", $lang, $userid);
        $stmt->execute();
        $stmt->close();
    }

    public function set_timezone($userid,$timezone)
    {
        $userid = (int) $userid;
        $timezone = preg_replace('/[^\w\-.\\/_]/','',$timezone);
        
        $stmt = $this->mysqli->prepare("UPDATE users SET timezone = ? WHERE id = ?");
        $stmt->bind_param("si", $timezone, $userid);
        $stmt->execute();
        $stmt->close();
    }

    //---------------------------------------------------------------------------------------
    // Special methods
    //---------------------------------------------------------------------------------------

    public function get_attributes(int $userid) {
        $result = $this->mysqli->query("SELECT name, value FROM user_attributes WHERE userid = $userid");
        
        if ($result === false) {
            // Handle the query error here
            return false;
        }
    
        $attributes = new stdClass(); // Create an empty object
    
        while ($row = $result->fetch_assoc()) {
            $attributes->{$row['name']} = json_decode($row['value']); // Use name as the key
        }
    
        return $attributes;
    }

    public function set_attribute(int $userid, string $name, $value) {        
        $stmt = $this->mysqli->prepare("INSERT INTO user_attributes (userid, name, value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE userid=?, name=?, value=?;");
        $j = json_encode($value);
        $stmt->bind_param("ississ", $userid, $name, $j, $userid, $name, $j);
        if (!$stmt->execute()) {
            $stmt->close();
            return array('success'=>false, 'message'=>_("Error updating user attribute"));
        }
        $stmt->close();
        return array('success'=>true);
    }
    
    public function get($userid)
    {
        $userid = (int) $userid;
        $result = $this->mysqli->query("SELECT id,username,email,gravatar,name,location,timezone,language,bio,startingpage,apikey_write,apikey_read,tags FROM users WHERE id=$userid");
        if (!$result) return array("success" => false, "message" => "Error fetching user data, you may need to run database update");
        $data = $result->fetch_object();
        return $data;
    }

    public function set($userid,$data)
    {
        global $settings;
        $default_locale = $settings["interface"]["default_language"];
        $default_timezone = 'Europe/London';
        // Validation
        $userid = (int) $userid;
        if(!$data || $userid < 1) return array('success'=>false, 'message'=>_("Error updating user info"));

        $gravatar = preg_replace('/[^\w\s\-.@]/','',$data->gravatar);
        $name = preg_replace('/[^\p{N}\p{L}_\s\-.]/u','',$data->name);
        $location = preg_replace('/[^\p{N}\p{L}_\s\-.]/u','',$data->location);
        $timezone = preg_replace('/[^\w\-.\\/_]/','',$data->timezone);
        $bio = preg_replace('/[^\p{N}\p{L}_\s\-.]/u','',$data->bio);
        $language = preg_replace('/[^\w\s\-.]/','',$data->language);
        $tags = isset($data->tags) == false ? '' : preg_replace('/[^{}",:\w\s\-.]/','', $data->tags);
        $startingpage = preg_replace('/[^\p{N}\p{L}_\s\-?#=\/]/u','',$data->startingpage);
        
        $_SESSION['lang'] = !empty($language) ? $language : $default_locale;
        $_SESSION['timezone'] = !empty($timezone) ? $timezone : $default_timezone;
        $_SESSION['gravatar'] = !empty($gravatar) ? $gravatar : '';

        $stmt = $this->mysqli->prepare("UPDATE users SET gravatar = ?, name = ?, location = ?, timezone = ?, language = ?, bio = ?, startingpage = ?, tags = ? WHERE id = ?");
        $stmt->bind_param("ssssssssi", $gravatar, $name, $location, $timezone, $language, $bio, $startingpage, $tags, $userid);
        if (!$stmt->execute()) {
            $stmt->close();
            return array('success'=>false, 'message'=>_("Error updating user info"));
        }
        $stmt->close();
    }

    // Generates a new random read apikey
    public function new_apikey_read($userid)
    {
        $userid = (int) $userid;
        $apikey = generate_secure_key(16);
        
        $stmt = $this->mysqli->prepare("UPDATE users SET apikey_read = ? WHERE id = ?");
        $stmt->bind_param("si", $apikey, $userid);
        $stmt->execute();
        $stmt->close();
        
        return $apikey;
    }

    // Generates a new random write apikey
    public function new_apikey_write($userid)
    {
        $userid = (int) $userid;
        $apikey = generate_secure_key(16);
        
        $stmt = $this->mysqli->prepare("UPDATE users SET apikey_write = ? WHERE id = ?");
        $stmt->bind_param("si", $apikey, $userid);
        $stmt->execute();
        $stmt->close();
        
        return $apikey;
    }

    public function get_number_of_users()
    {
        $result = $this->mysqli->query("SELECT COUNT(*) FROM users");
        $row = $result->fetch_row();
        return $row[0];
    }

    public function get_email_by_username($username) {
        $stmt = $this->mysqli->prepare("SELECT email FROM users WHERE username=?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($email);
        $stmt->fetch();
        $stmt->close();
        if ($email == "") {
            throw new InvalidUserException("No email found for ".$username);
        }
        return $email;
    }
    
    public function get_usernames_by_email($email) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return false;
        $stmt = $this->mysqli->prepare("SELECT id, username FROM users WHERE email=?");
        $stmt->bind_param("s", $email);
        $stmt->execute();        
        $stmt->bind_result($id,$username);
        
        $users = array();
        while ($stmt->fetch()) {
            $users[] = array("id"=>$id,"username"=>$username);
        }
        $stmt->close();

        if (empty($users)) {
            throw new InvalidUserException("No usernames associated with ".$email);
	}
	
        return $users;
    }
    /**
     * return true if input is not null
     *
     * @param mixed $var
     * @return boolean
     */
    private function is_not_null ($var) {
        return !is_null($var);
    }
}

class InvalidUserException extends Exception {

}
