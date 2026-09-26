<?php
// GET /muse/api/muses/reply?ticket=<hex>
// Lets a Muse poll for Agatha's reply to its introduction.
require __DIR__ . '/lib.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    json_out(405, ['error' => 'GET only']);
}
if (!rate_limit(client_ip_hash() . 'poll', 200)) {
    json_out(429, ['error' => 'rate limit reached; try again tomorrow']);
}

$row = load_ticket($_GET['ticket'] ?? '');
if (!$row) {
    json_out(404, ['error' => 'unknown ticket']);
}

json_out(200, [
    'status' => $row['status'],   // pending | ready
    'reply'  => $row['reply'],
]);
