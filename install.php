<?php

error_reporting(E_ALL);

$db_type = "sqlite";
$db_path = "users.db";

$db_connection = new PDO($db_type . ':' . $db_path);
 

// create new empty table inside the database (if table does not already exist)
$sql = 'CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        user_name varchar(64),
        user_password_hash varchar(255),
        user_email varchar(64));
        CREATE UNIQUE INDEX `user_name_UNIQUE` ON users (user_name ASC);
        CREATE UNIQUE INDEX `user_email_UNIQUE` ON users (user_email ASC);
        ';

$query = $db_connection->prepare($sql);
$query->execute();

//did it work?

if(file_exists($db_path))
{
	echo "Database $db_path was created, installation was succesfull.";
}
else
{
	echo "Database $db_path was not created, installion failed, Missing folder write rights?";
}

?>