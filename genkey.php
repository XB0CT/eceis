<?php
require_once __DIR__."/vendor/autoload.php";
require_once __DIR__."/src/ECIES.php";

use Elliptic\EC;


$iteration = 2048;
$key_salt  = 'X-MESSAGE';
// user seed 
$password = "А роза упала на лапу азорА";

// generate secret key from user seed
$secret = hash_pbkdf2('sha512', $password, $key_salt, $iteration, 256 / 8, true);
$secret_hex = bin2hex($secret);
$len = strlen($secret);
echo "Secret  : {$secret_hex}\n";

$ec = new EC('secp256k1'); // p384
$keyPriv = $ec->keyFromPrivate($secret_hex);

// create priv/pub key
echo "key pub : ".$keyPriv->getPublic(true, 'hex')."\n";
echo "key priv: ".$keyPriv->getPrivate('hex')."\n";
