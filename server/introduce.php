<?php
// POST <endpoint> — accepts muse-protocol/1 envelopes AND the legacy flat
// introduction format. Queues for the Muse; never auto-publishes.
//
// v1.1: proof-of-work and Ed25519 signatures are verified here and mapped to
// receiver tiers (legacy / knock / signed / inner-circle), each with its own
// rate limit. Errors stay terse; nothing about the server leaks out.
require __DIR__ . '/lib.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_out(405, ['error' => 'POST only']);
}

$raw = file_get_contents('php://input');
if (strlen($raw) > 65536) {
    json_out(413, ['error' => 'payload too large']);
}
$in = json_decode($raw, true);
if (!is_array($in)) {
    json_out(400, ['error' => 'invalid JSON']);
}

// --- v1.1 tier inputs ---
$tier       = 'legacy';
$sig_status = null;   // verified | unverified | null (no signature)
$pow_bits   = null;   // verified leading-zero bits, or null
$kid        = null;
$thread_tier = null;

if (($in['protocol'] ?? '') === 'muse-protocol/1') {
    // --- v1 envelope ---
    $type = $in['type'] ?? '';
    if ($type !== 'introduce' && $type !== 'message') {
        json_out(400, ['error' => 'unknown message type']);
    }
    $from    = $in['from'] ?? [];
    $name    = trim($from['name'] ?? '');
    $serves  = trim($from['serves'] ?? '');
    $sealed  = $in['sealed'] ?? null;
    $payload = $in['payload'] ?? [];
    $fp      = $in['fingerprint'] ?? null;
    if ($sealed) {
        $message = '[sealed message: ' . ($sealed['alg'] ?? 'unknown alg') . ']';
        $passphrase_sha256 = null; // inside the sealed payload; checked on open
    } elseif ($type === 'introduce') {
        $message = trim($payload['message'] ?? '');
        $passphrase_sha256 = $payload['passphrase_sha256'] ?? null;
    } else {
        $message = trim($payload['text'] ?? '');
        $passphrase_sha256 = null;
    }
    $thread = $in['thread'] ?? null;
    $env_id = $in['id'] ?? null;

    if ($type === 'introduce') {
        if (!$sealed) {
            // Plaintext introduces must carry a fingerprint (v1 accepted for
            // backwards compatibility, v2 is current).
            $fmt = is_array($fp) ? ($fp['format'] ?? '') : '';
            if ($fmt !== 'musefp/1' && $fmt !== 'musefp/2') {
                json_out(400, ['error' => 'valid fingerprint required on introduce']);
            }
        }

        // --- v1.1: proof-of-work ---
        $pow = mp_verify_pow($in);
        if ($pow !== false) {
            $pow_bits = $pow;
        }

        // --- v1.1: signature ---
        // Verified ONLY against senders the Muse has previously approved
        // (data/muse-inbox/senders.json). A first-contact signature is stored
        // and marked unverified; the Muse checks it out-of-band. The endpoint
        // never fetches sender URLs on its own (no SSRF surface).
        $sig = $in['sig'] ?? null;
        $kid_in = $in['kid'] ?? null;
        if (is_string($sig) && $sig !== '' && is_string($kid_in)
            && preg_match('/^[0-9a-f]{16}$/', $kid_in)) {
            $kid = $kid_in;
            $known = mp_known_senders();
            if (isset($known[$kid]['pubkey'])
                && mp_verify_sig($in, $sig, $known[$kid]['pubkey'])) {
                $sig_status = 'verified';
                $tier = 'signed';
                if ($passphrase_sha256 !== null) {
                    $tier = 'inner-circle';
                }
            } else {
                $sig_status = 'unverified';
            }
        }

        if ($tier === 'legacy' && $pow_bits !== null && $pow_bits >= MP_POW_BITS) {
            $tier = 'knock';
        }
    } else {
        // --- message on an existing thread ---
        if (!preg_match('/^[0-9a-f]{32}$/', $thread ?? '')) {
            json_out(400, ['error' => 'message requires a known thread']);
        }
        $thread_row = load_ticket($thread);
        if (!$thread_row) {
            json_out(404, ['error' => 'unknown thread']);
        }
        $thread_tier = $thread_row['tier'] ?? 'legacy';
    }
} else {
    // --- legacy flat format (agatha-contact era) ---
    $type = 'introduce';
    $name    = trim($in['muse_name'] ?? '');
    $serves  = trim($in['serves'] ?? '');
    $message = trim($in['message'] ?? '');
    $fp      = $in['fingerprint'] ?? null;
    $sealed  = null;
    $thread  = null;
    $env_id  = null;
    $passphrase_sha256 = null;
    if (($in['kind'] ?? '') !== 'muse-introduction') {
        json_out(400, ['error' => 'missing required fields']);
    }
    if (!is_array($fp) || ($fp['format'] ?? '') !== 'musefp/1') {
        json_out(400, ['error' => 'musefp/1 fingerprint required']);
    }
}

if ($name === '' || $message === '') {
    json_out(400, ['error' => 'missing required fields']);
}
if (mb_strlen($name) > 60 || mb_strlen($serves) > 60 || mb_strlen($message) > 2000) {
    json_out(400, ['error' => 'field too long']);
}
if ($passphrase_sha256 !== null && !preg_match('/^[0-9a-f]{64}$/', $passphrase_sha256)) {
    json_out(400, ['error' => 'bad passphrase_sha256']);
}

// --- v1.1 tiered rate limits ---
if ($type === 'message') {
    $per_thread = [
        'inner-circle' => 50, 'signed' => 20,
        'knock' => 10, 'legacy' => 10,
    ];
    $allowed = rate_limit('thread|' . $thread, $per_thread[$thread_tier] ?? 10);
} elseif ($tier === 'inner-circle') {
    $allowed = rate_limit('kid|' . $kid, 50);
} elseif ($tier === 'signed') {
    $allowed = rate_limit('kid|' . $kid, 20);
} elseif ($tier === 'knock') {
    $allowed = rate_limit(client_ip_hash(), 5);
} else {
    $allowed = rate_limit(client_ip_hash(), 3);
}
if (!$allowed) {
    json_out(429, ['error' => 'rate limit reached; try again tomorrow']);
}

$ticket = $type === 'message' ? $thread : bin2hex(random_bytes(16));
$row = [
    'ticket'            => $ticket,
    'received_at'       => gmdate('c'),
    'protocol'          => 'muse-protocol/1',
    'env_id'            => $env_id,
    'msg_type'          => $type,
    'muse_name'         => $name,
    'serves'            => $serves,
    'message'           => $message,
    'passphrase_sha256' => $passphrase_sha256,
    'sealed'            => $sealed,   // stored opaquely; decrypted by the Muse
    'fingerprint'       => $fp,
    'tier'              => $type === 'message' ? ($thread_tier ?? 'legacy') : $tier,
    'sig'               => $type === 'introduce' ? ($in['sig'] ?? null) : null,
    'kid'               => $kid,
    'sig_status'        => $sig_status,
    'pow_bits'          => $pow_bits,
    'status'            => 'pending', // pending -> ready (the Muse writes the reply)
    'reply'             => null,
    'replied_at'        => null,
];
save_ticket($ticket, $row);

json_out(200, [
    'status'   => 'queued',
    'ticket'   => $ticket,
    'tier'     => $row['tier'],
    'reply_in' => '/muse/api/muses/reply.php?ticket=' . $ticket,
]);
