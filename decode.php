<?php
require_once __DIR__ . "/vendor/autoload.php";
require_once __DIR__ . "/src/ECIES.php";

use Elliptic\EC;
use StephenHill\Base58;

$iteration = 2048;
$key_salt  = 'X-MESSAGE';
// user seed 
$password = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

// generate secret key from user seed
$secret = hash_pbkdf2('sha512', $password, $key_salt, $iteration, 256 / 8, true);
$secret_hex = bin2hex($secret);
$len = strlen($secret);
echo "Secret  : {$secret_hex}\n";

$ec = new EC('secp256k1'); // p384
$b58 = new Base58();
$keyPriv = $ec->keyFromPrivate($secret_hex);

// create priv/pub key
echo "key pub : ".$keyPriv->getPublic(true, 'hex')."\n";
echo "key priv: ".$keyPriv->getPrivate('hex')."\n\n";

// decode incomming message
$msg = "8aYYGXbGxZoUs3DcuBcEEcXsJyeJRhdQd16K5MxbUoirhtXcuXHi3MhPNNKaT6nFppQKe7jwqw7QhGLf59nyxb1Xar61ju3kPYGyfbcbgWt25PJ9qXKku75j3fDdJiTdJYfanzUEmmt6sSCxeVog71Uu7MsN5UPabeAj66ztNrq7bP27i89n4";
$msg = bin2hex($b58->decode($msg));

// just debug
echo "msg     : {$msg}\n";

$remotePub = substr($msg, 0, 66);
$ivhex = substr($msg, 66, 32);
$msg = substr($msg, 66);

// just debug
echo "pub msg : {$remotePub}\n";
echo "iv  msg : {$ivhex}\n";
echo "message : {$msg}\n\n";


$remotePubKey = $ec->keyFromPublic(hex2bin($remotePub));
//echo "key pub : ".$remotePubKey->getPublic(true, 'hex')."\n";
$ecies1 = new ECIES($keyPriv, $remotePubKey);

// just debug
echo "EkM     : ".bin2hex($ecies1->getkEkM())."\n";
echo " kE     : ".bin2hex($ecies1->getkE())."\n";
echo " kM     : ".bin2hex($ecies1->getkM())."\n\n";

$iv = hex2bin($ivhex);
$cipher = $ecies1->decrypt(hex2bin($msg));
// openssl error(s)
while ( $msg = openssl_error_string() ) echo "{$msg}\n";

// finally decoded message
echo "message : " . $cipher . "\n";