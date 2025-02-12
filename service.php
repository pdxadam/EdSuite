<?php
    header("Access-Control-Allow-Origin: http://localhost:5173");
    header('Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS');
    header('Access-Control-Max-Age: 1000');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
    header('Access-Control-Allow-Credentials: true');
    session_start();
    error_log("---- new request ---");
    error_log(print_r($_POST), true);
    require_once("dbConn.php");
    
    $db = getConn();
    if ($db === false){
        error_log("Error 01: could not connect to database");
        echo("Error 01: data connection failed");
        die();
    }
    $rq = filter_input(INPUT_POST, "rq", FILTER_VALIDATE_INT);
    error_log("RQ is " . $rq);
    switch($rq){
        case 5:
            //testing the interaction
            $d = filter_input(INPUT_POST, "data", FILTER_DEFAULT);
            echo("You sent me: " . $d);
            break;
        case 6: 
            echo("Requested 6");
            echo("Username: " . $_SESSION['userName']);
            break;
        case 10:
            //login
            //u (username), p(password), a(appID)
            try{
                $u = filter_input(INPUT_POST, "u", FILTER_DEFAULT);
                $p = filter_input(INPUT_POST, "p", FILTER_DEFAULT);
                $app = filter_input(INPUT_POST, "app", FILTER_VALIDATE_INT);
                $results = checkLogin($u, $p, $db);
                if ($results === true){
                    
                    $_SESSION['appID'] = $app;//storing as session so this one can only do this app
                    $appData = getApp($db);
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
        case 50:
            //create account
            //Right now, any old schmuck can create an email
            $u = filter_input(INPUT_POST, 'username', FILTER_DEFAULT);
            $p = filter_input(INPUT_POST, 'password', FILTER_DEFAULT);
            $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
            if ($email == false){
                error_log("Error 500.  invalid email " . $email);
                echo ("Error 500: invalid email");
                session_destroy();
                break;
            }
            $result = createUser($u, $p, $email, $db);
            session_destroy();
            echo($result[1]);
            //if we create the user, we'll tell them success.  If it fails, we'll tell them so. 
            //if success, they need to proceed to login.
            //if failure, they need to try again, or contact support.

            break;
        case 100:
            //logout
            session_destroy();
            echo("User logged out");
            break;



    }
    $db = null; //close the database every time.

    // ----- end of main code, functions after--------------------------------
    
    function userExists($u, $db){ // returns true if the username is taken. False if it is not
        $sql = $db->prepare("SELECT count(*) as myCount FROM tblUser WHERE userName = :u");
        $sql->bindValue(":u", $u);
        if ($sql->execute()){
                $row = $sql->fetch(PDO::FETCH_ASSOC);
                return $row['myCount'] == 1;
        }
        else{
            return false;
        }
    }
    function checkLogin($u, $p, $db = null){
        //returns true and sets $_SESSION[pkUser] if success
        //returns array of [false, "error message"] if failed
        if ($db == null){
            $db = getConn();
        }
        $sql = $db->prepare("SELECT * FROM tblUser WHERE username = :username");
        $sql->bindValue(":username", $u);
        if ($sql->execute()){
            $rows = $sql->fetchAll(PDO::FETCH_ASSOC);
            if (count($rows) == 1){
                //there is one user
                if (password_verify($p, $rows[0]['password'])){
                    //check if we need to rehash
                    if (password_needs_rehash($rows[0]['password'], PASSWORD_DEFAULT)){
                        //then we need to update the password to what it already is.
                    }
                    $_SESSION['pkUser'] = $rows[0]['pkUser'];
                    $_SESSION['userName'] = $u;
                    
                    return(true); //now it needs to request the right app
                }
                else{
                    error_log("Error 101: invalid authentication request: invalid password for user '" . $u . "'");
                    return [false, "Error 101: Authentication failed"];
                }
            }
            else{
                session_destroy();
                error_log("Error 101: invalid authentication request: no user found for user '" . $u . "' password " . $p );
                return [false,"Error 101: Authentication failed"];

            }
        }
        else{
            session_destroy();
            error_log("Error 102: authentication failed for user '" . $u . "'");
            return [false, "Error 102: Authentication failed"];
        }
        
    }
    function createUser($u, $p, $email, $db){
        if (userExists($u, $db)){
            error_log("Error 502: Attempt to create duplicate user '" . $u . "'");
            return [false, "Error 502: Username is taken"];
        }
        $sql = $db->prepare("INSERT INTO tblUser (username, email, password) VALUES(:u, :e, :p)");
        $sql->bindValue(":u", $u);
        $sql->bindValue(":p", password_hash($p, PASSWORD_DEFAULT));
        $sql->bindValue(":e", $email);
        if ($sql->execute()){         
            return [true, "User created. Please login."];
        }
        else{
            error_log("Error 503: Failed creating user '" . $u . "' with email '" . $email . "'");
            return [false, "Error 503: Error creating user"];
        }


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
