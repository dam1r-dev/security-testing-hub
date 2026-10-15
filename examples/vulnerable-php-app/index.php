<?php
// A deliberately vulnerable script: a fixture for the scanner's tests. Do not deploy.
$conn = new mysqli("localhost", "app", "app", "shop");

// SQL injection
$name = $_GET['name'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'");

// safe: an integer cast
$id = (int) $_GET['id'];
mysqli_query($conn, "SELECT * FROM users WHERE id = $id");

// safe: a prepared statement
$stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
$stmt->bind_param("s", $_POST['email']);
$stmt->execute();

// reflected XSS
echo "<h1>Hello " . $_GET['who'] . "</h1>";

// safe
echo "<h1>Hello " . htmlspecialchars($_GET['who'], ENT_QUOTES, 'UTF-8') . "</h1>";

// command injection
system("ping -c 1 " . $_GET['host']);

// local file inclusion
include $_GET['page'] . ".php";

// path traversal
echo file_get_contents("/var/www/uploads/" . $_GET['file']);

// insecure deserialization
$data = unserialize($_COOKIE['session_data']);

// open redirect
header("Location: " . $_GET['next']);

// code injection
eval($_POST['code']);

// SSRF
$ch = curl_init($_GET['url']);

// debug output left on
ini_set('display_errors', '1');

// hard-coded credential
$db_password = "Pr0d-DB!pass#2024xYz";

function lookup($who) {
    global $conn;
    return mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $who . "'");
}
lookup($_GET['q']);   // SQL injection through a helper
