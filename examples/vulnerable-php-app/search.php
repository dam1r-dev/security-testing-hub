<?php
require __DIR__ . '/lib/db.php';

$rows = find_user_by_name($_GET['n']);          // SQL injection in another file
$safe = find_user_safe($_GET['n']);             // safe: a prepared statement there
echo report_for($_GET['kind']);                 // command injection two hops away
