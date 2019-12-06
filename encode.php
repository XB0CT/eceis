<?php
require_once __DIR__."/vendor/autoload.php";
require_once __DIR__."/src/ECIES.php";

use Elliptic\EC;
use StephenHill\Base58;


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

$msg = "This messages is private! Это частное сообщение!";

// seed = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
$remotePub = "0312fd5c918b02ae438fd8a316cd312389b9efa4ae3c525fbce7d2cfa27280943e";
$remotePubKey = $ec->keyFromPublic(hex2bin($remotePub));

// encode message with remote Public key
$ecies = new ECIES($keyPriv, $remotePubKey);
// create random initialization vector
$iv = $ecies->makeIV();
// encrypt
$cipher = $ecies->encrypt($msg, $iv);

// build message to send user with $remotePub
$b58 = new Base58();
$sendMessage = $b58->encode(hex2bin($keyPriv->getPublic(true, 'hex').bin2hex($cipher)));

echo "send    : {$sendMessage}\n";
