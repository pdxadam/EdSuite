<?php
    require_once("dbConn.php");
    if (session_status() != PHP_SESSION_ACTIVE){
        session_start();
    }
    $db = getConn();
    if ($db === false){
        echo("Error: data connection failed");
        die();
    }
    $rq = filter_input(INPUT_POST, "rq", FILTER_VALIDATE_INT);
    switch($rq){
        case 10:
            //login?
            //u (username), p(password), a(appID)
            $u = filter_input(INPUT_POST, "u", FILTER_DEFAULT);
            $p = filter_input(INPUT_POST, "p", FILTER_DEFAULT);
            $app = filter_input(INPUT_POST, "app", FILTER_VALIDATE_INT);
            checkLogin($u, $p, $app, $db);
            break;
        case 20:
            //connect app
            //validate user authentication.authorization first
            break;
            
        case 30:
            //get data
            break;
        case 40: 
            //put data
            break;
        case 50:
            //create account
            break;
        



    }
    $db = null; //close the database every time.
    function checkLogin($u, $p, $a, $db = null){
        if ($db = null){
            $db = getConn();
        }
        $sql = $db->prepare("SELECT * FROM tblUser WHERE username = :username");
        $sql->bindValue(":username", $u);
        if ($sql->execute()){
            $rows = $sql->fetchAll(PDO::FETCH_ASSOC);
            if (count($rows) == 1){
                //there is one user
                $_SESSION['pkUser'] = $rows[0]['pkUser'];
                echo("Success");


            }
            else{
                session_destroy();
                echo("Error: Authentication failed");

            }
        }
        
    }
