<?php
function db() {
    static $conn;
    return $conn ??= new mysqli("localhost", "app", "app", "shop");
}

function find_user_by_name($name) {
    return mysqli_query(db(), "SELECT * FROM users WHERE name = '$name'");   // the SQL is built here
}

function find_user_safe($name) {
    $stmt = db()->prepare("SELECT * FROM users WHERE name = ?");
    $stmt->bind_param("s", $name);
    return $stmt->execute();
}

function run_report($kind) {
    return shell_exec("report --kind " . $kind);
}

function report_for($kind) {
    return run_report($kind);   // one more hop
}
