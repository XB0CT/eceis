<?php
require_once __DIR__ . "/vendor/autoload.php";
require_once __DIR__ . "/src/ECIES.php";

use Elliptic\EC;
use StephenHill\Base58;

$iteration = 2048;
$key_salt  = 'X-MESSAGE';

$password = "А роза упала на лапу азорАqwe";
$secret = hash_pbkdf2('sha512', $password, $key_salt, $iteration, 256 / 8, true);
$secret_hex = bin2hex($secret);
$len = strlen($secret);
echo "Secret  : {$secret_hex}\n";


$ec = new EC('secp256k1'); // p384
$b58 = new Base58();
$keyPriv = $ec->keyFromPrivate($secret_hex);

echo "key pub : ".$keyPriv->getPublic(true, 'hex')."\n";
echo "key priv: ".$keyPriv->getPrivate('hex')."\n\n";


/* JS
var ec = elliptic.ec('secp256k1');
var priv2 = ec.keyFromPrivate('c05e44d945c5533d1b3ff314d260520d382f448f85035b8f86f1c02a853755e7', 'hex');
var pub1 = ec.keyFromPublic('0270f650ba2033ff312d8d648a07a3143ea841b38277e25cfe09f2b170063c8a7c', 'hex');

var shared = k.derive(pub1.getPublic());
*/

$msg = "2E6a7tCt1UENFoVUJgDSdyesaCRriYwSpyWN77EvVCCBqYPuehWQHcGSruEgM8xwyJKNg6Y6B163LAVkitQoAEuuXEeWuNLwntUgnpjf6W5XHcWakbeq";
$msg = bin2hex($b58->decode($msg));

echo "msg     : {$msg}\n";
$pub   = substr($msg, 0, 66);
$ivhex = substr($msg, 66, 32);
echo "pub msg : {$pub}\n";
echo "iv  msg : {$ivhex}\n";
$msg   = substr($msg, 66);
echo "message : {$msg}\n\n";


$key2Pub = $ec->keyFromPublic(hex2bin($pub));
//echo "key pub : ".$key2Pub->getPublic(true, 'hex')."\n";
$ecies1 = new ECIES($keyPriv, $key2Pub);
echo "EkM     : ".bin2hex($ecies1->getkEkM())."\n";
echo " kE     : ".bin2hex($ecies1->getkE())."\n";
echo " kM     : ".bin2hex($ecies1->getkM())."\n\n";

$iv = hex2bin($ivhex);
$cipher = $ecies1->decrypt(hex2bin($msg));
while ( $msg = openssl_error_string() ) echo "{$msg}\n";
var_dump($cipher);
echo "message : " . $cipher . "\n";

