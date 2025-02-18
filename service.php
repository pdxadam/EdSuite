<?php
    // 2/17/2025: switching to login by email instead of username
    
    $allowedOrigins = ["http://localhost:5173","http://localhost:5174"];
    if(in_array($_SERVER['HTTP_ORIGIN'], $allowedOrigins))
    {
	    $http_origin = $_SERVER['HTTP_ORIGIN'];
    } else {
        error_log($http_origin);
	    $http_origin = "http://localhost:5173";
    }
    header("Access-Control-Allow-Origin: " . $http_origin);
    header('Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS');
    header('Access-Control-Max-Age: 1000');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
    header('Access-Control-Allow-Credentials: true');
    session_start();

    error_log("---- new request ---");
    // error_log(print_r($_POST), true);
    require_once("dbConn.php");
    
    $db = getConn();
    if ($db === false){
        error_log("Error 01: could not connect to database");
        echo("Error 01: data connection failed");
        die();
    }
    $rq = filter_input(INPUT_POST, "rq", FILTER_VALIDATE_INT);
    if (!$rq){
        $rq = filter_input(INPUT_GET, "rq", FILTER_VALIDATE_INT);
    }
    error_log("RQ is " . $rq);
    if (!isset($_SESSION['pkUser']) && $rq > 10){
        echo("Error 1: Not logged in");
        die();
    }
    switch($rq){
        case 5:
            //create account
            //Right now, any old schmuck can create an email
            $u = filter_input(INPUT_POST, 'u', FILTER_DEFAULT);
            $p = filter_input(INPUT_POST, 'p', FILTER_DEFAULT);
            $email = filter_input(INPUT_POST, 'e', FILTER_VALIDATE_EMAIL);
            if ($email == false){
                error_log("Error 50.  invalid email " . $email);
                echo ("Error 50: invalid email");
                session_destroy();
                break;
            }
            $result = createUser($u, $p, $email, $db);
            session_destroy();
            if ($result[0] == true){
                echo("Success");
            }
            else{
                echo($result[1]);
            }
            //if we create the user, we'll tell them success.  If it fails, we'll tell them so. 
            //if success, they need to proceed to login.
            //if failure, they need to try again, or contact support.

            break;
        case 6:
            //activate account
            $email = filter_input(INPUT_GET, "email", FILTER_VALIDATE_EMAIL);
            //find the user
            $code = filter_input(INPUT_GET, "ac", FILTER_DEFAULT);
            $results = checkActivationCode($email, $code, $db);
            if ($results[0] == true){
                echo("<h1>Congratulations</h1>Your registration has been verified. Please close this window and return to the application");
            }
            else{
                echo("<h1>Oops</h1>It seems there was an error. Please contact our support team.");
            }
            break;
    
        case 10:
            //login
            //e (email), p(password), a(appID)
            try{
                $e = filter_input(INPUT_POST, "e", FILTER_VALIDATE_EMAIL);
                $p = filter_input(INPUT_POST, "p", FILTER_DEFAULT);
                $app = filter_input(INPUT_POST, "app", FILTER_VALIDATE_INT);
                $results = checkLogin($e, $p, $db);
                if ($results === true){
                    
                    $_SESSION['appID'] = $app;//storing as session so this one can only do this app
                    echo("Success.");
                    
                    
                
                }
                else{
                    session_destroy(); //kill the session if we ran into an unexpected error
                   echo($results[1]);
                    
                    break;
                }
            }
            catch (Exception $e){
                error_log($e);
            }
            
            
            break;
        case 20:
            //connect app
            //validate user authentication.authorization first
            //make sure the app is correct (i.e. it is an app that I accept)
            break;
            
        case 30:
            //get data
            $result = getApp($db);
            echo($result[1]);

            break;
        case 40: 
            //put data
            //d data
            
            $data = filter_input(INPUT_POST, "d", FILTER_DEFAULT);
            $result = putData($data, $db);
            echo($result[1]);
            
            break;
        
        case 100:
            //logout
            session_destroy();
            echo("User logged out");
            break;
       
        default:
            echo("Error: request not recognized");

    }
    $db = null; //close the database every time.

    // ----- end of main code, functions after--------------------------------
    
    function userExists($e, $db){ // returns true if the username is taken. False if it is not
        $sql = $db->prepare("SELECT count(*) as myCount FROM tblUser WHERE email = :e");
        $sql->bindValue(":e", $e);
        if ($sql->execute()){
                $row = $sql->fetch(PDO::FETCH_ASSOC);
                return $row['myCount'] == 1;
        }
        else{
            return false;
        }
    }
    function checkLogin($e, $p, $db = null){
        //returns true and sets $_SESSION[pkUser] if success
        //returns array of [false, "error message"] if failed
        if ($db == null){
            $db = getConn();
        }
        $sql = $db->prepare("SELECT * FROM tblUser WHERE email = :email AND active = 1");
        $sql->bindValue(":email", $e);
        if ($sql->execute()){
            $rows = $sql->fetchAll(PDO::FETCH_ASSOC);
            if (count($rows) == 1){
                //there is one user
                if (password_verify($p, $rows[0]['password'])){
                    //check if we need to rehash
                    if (password_needs_rehash($rows[0]['password'], PASSWORD_DEFAULT)){
                        //then we need to update the password to what it already is.
                    }
                    session_regenerate_id();
                    $_SESSION['pkUser'] = $rows[0]['pkUser'];
                    $_SESSION['email'] = $e;
                    $_SESSION['username'] = $rows[0]['email'];
                    
                    return(true); //now it needs to request the right app
                }
                else{
                    error_log("Error 101: invalid authentication request: invalid password for email '" . $e . "'");
                    return [false, "Error 101: Authentication failed"];
                }
            }
            else{
                session_destroy();
                error_log("Error 101: invalid authentication request: no user found for user '" . $e . "' password " . $p );
                return [false,"Error 101: Authentication failed"];

            }
        }
        else{
            session_destroy();
            error_log("Error 102: authentication failed for user '" . $e . "'");
            return [false, "Error 102: Authentication failed"];
        }
        
    }
    function createUser($u, $p, $email, $db){
        $activationCode = bin2hex(random_bytes(16));
        if (userExists($email, $db)){
            error_log("Error 52: Attempt to create duplicate user '" . $u . "'");
            return [false, "Error 52: That account already exists. Please login"];
        }

        $sql = $db->prepare("INSERT INTO tblUser (username, email, password, activation_code, activation_expiry) VALUES(:u, :e, :p, :ac, :ae)");
        $sql->bindValue(":u", $u);
        $sql->bindValue(":p", password_hash($p, PASSWORD_DEFAULT));
        $sql->bindValue(":e", $email);
        $sql->bindValue(":ac", password_hash($activationCode, PASSWORD_DEFAULT));
        $sql->bindValue(":ae", date('Y-m-d H:i:s', time() + (1 * 24 * 60 * 60)));
        if ($sql->execute()){    
            sendActivationLink($email, $activationCode);     
            return [true, "User created. Please check your email to activate your account. Message will come from no_reply@mclainonline.com"];
        }
        else{
            error_log("Error 53: Failed creating user '" . $u . "' with email '" . $email . "'");
            return [false, "Error 53: Error creating user"];
        }



    }
    function sendActivationLink(string $email, string $activationCode){
        
        $activationLink = "https://mclainonline.com/EdSuite/service.php?rq=6&email=$email&ac=$activationCode";
        error_log("activation link: " . $activationLink);
        $subject = 'Please activate your account';
        $message = <<<MESSAGE
            Hi, 
            Please click the following link to activate your account: 
            $activationLink
            MESSAGE;
        $header = "From: no-reply@mclainonline.com";
        mail($email, $subject, nl2br($message), $header);
        error_log("sent $message to $email");

    }
    function checkActivationCode($email, $code, $db){        
        //find the user
        $sql = $db->prepare("SELECT pkUser, activation_code, activation_expiry < now() as expired FROM tblUser WHERE active = 0 and email = :email;");
        $sql->bindValue(":email", $email);
        if ($sql->execute()){
            $user = $sql->fetch(PDO::FETCH_ASSOC);
            error_log($user['pkUser']);
            if ($user){
                if ($user['expired'] === 1){
                    error_log("Expired code");
                    deleteUserById($user['id'], $db); //delete them because the activation expire
                    return [false, "expired activation, please register"];
                }
                error_log("Activation code: " . $code);
                error_log("hashed activation code: " . password_hash($code, PASSWORD_DEFAULT));
                error_log("data hash: " . $user['activation_code']);
                if (password_verify($code, $user['activation_code'])){
                    //now it's time to active the user
                    error_log("Excellent. Now we can activate the user");
                    return activateUser($user['pkUser'], $db);
                }
                else{
                    error_log("Invalid activation code");
                }
    
            }
        }
        else{
            error_log("Error selecting user: ");
        }
        error_log("At the end with no results");
        return [false, "Error retrieving user"];

    }
    function activateUser(int $userID, $db){
        $sql = $db->prepare("UPDATE tblUser SET active = 1, 
            activated_at = CURRENT_TIMESTAMP WHERE pkUser = :id");
        $sql->bindValue(":id", $userID, PDO::PARAM_INT);
        return [$sql->execute(), ""];
    }
    function deleteUserById($id, $db){
        $sql = $db->prepare("DELETE FROM tblUser WHERE pkUser = :id");
        $sql->bindValue(":id", $id, PDO::PARAM_INT);
        return [$sql->execute(), ""];

    }
    function getApp($db){
        $sql = $db->prepare("SELECT * FROM tblData WHERE fkApp = :app AND fkOwner = :user");
        $sql->bindValue(":app", $_SESSION['appID'], PDO::PARAM_INT);
        $sql->bindValue(":user", $_SESSION['pkUser'], PDO::PARAM_INT);
        if ($sql->execute()){
            $rows = $sql->fetchAll(PDO::FETCH_ASSOC);
            //should always be only one
            if (count($rows) == 1){
                return([true,$rows[0]['data']]);

            }
            else if (count($rows) == 0){
                //they don't have this app yet. Insert it?
                
                return [false, "Error 300: App not yet connected"];
            }
            else{
                //they've logged in, but they don't have this app
                error_log("Error 302: Incorrect data row count. app " . $_SESSION['appID'] . " user " . $_SESSION['pkUser']);
                return [false, "Error 301: Incorrect data count: " . count($rows)];
            }

        }
    }
    function putData($data, $db){
        //if the app/owner exists, we'll update it. 
        //if not, we'll create it.
        //need to validate the data structure as it comes in.
        $res = getApp($db);
        if ($res[0] == false){
            if (str_starts_with($res[1], "Error 300")){
                //there's no data there, we need to create it.
                $sql = $db->prepare("INSERT INTO tblData (fkApp, fkOwner, data) VALUES (:app, :owner, :data);");
                $sql->bindValue(":app", $_SESSION['appID']);
                $sql->bindValue(":owner", $_SESSION['pkUser']);
                $sql->bindValue(":data", $data);
                if ($sql->execute()){
                    return [true, "Success: App data created"];
                }
                else{
                    error_log("Error 401: user: " . $_SESSION['pkUser'] . " app: " . $_SESSION['appID'] . " Data: " . $data);
                    return [false, "Error 401: App data creation failed."];
                }
                 }
            else{
                error_log("Error 402: user: " . $_SESSION['pkUser'] . " app: " . $_SESSION['appID'] . " Data: " . $data);
                return [false, "Error 402: User Data structure is corrupt. Contact support"];
            }
        }
        else{
            //we need to update the data in the table
            $sql = $db->prepare("UPDATE tblData SET data = :data WHERE fkOwner = :owner AND fkApp = :app");
            $sql->bindValue(":app", $_SESSION['appID']);
            $sql->bindValue(":owner", $_SESSION['pkUser']);
            $sql->bindValue(":data", $data);
            if ($sql->execute()){
                return [true, "Data updated successfully"];
            }
            else{
                error_log("Error 403: " . $sql->error_get_last());
                return [false, "Error 403: Database Error updating data"];
            }
        } 
    
    }
