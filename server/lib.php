<?php
// Shared helpers for the Muses API.
// Data lives outside the web root: <site-home>/data/muse-inbox (0700).

// Minimum proof-of-work for the "knock" tier (leading zero bits).
const MP_POW_BITS = 20;

function muse_data_dir() {
    $d = dirname(__DIR__, 3) . '/data/muse-inbox';
    if (!is_dir($d)) mkdir($d, 0700, true);
    return $d;
}

function json_out($code, $obj) {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($obj);
    exit;
}

function client_ip_hash() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return hash('sha256', 'muse-inbox|' . $ip);
}

// Simple per-day counter. Returns true if the action is allowed.
function rate_limit($key, $max_per_day) {
    $dir = muse_data_dir() . '/ratelimit';
    if (!is_dir($dir)) mkdir($dir, 0700, true);
    $f = $dir . '/' . preg_replace('/[^0-9a-f]/', '', $key) . '.json';
    $today = gmdate('Y-m-d');
    $row = ['date' => $today, 'count' => 0];
    if (is_file($f)) {
        $row = json_decode(file_get_contents($f), true) ?: $row;
        if (($row['date'] ?? '') !== $today) $row = ['date' => $today, 'count' => 0];
    }
    if (($row['count'] ?? 0) >= $max_per_day) return false;
    $row['count']++;
    file_put_contents($f, json_encode($row), LOCK_EX);
    return true;
}

function load_ticket($ticket) {
    if (!preg_match('/^[0-9a-f]{32}$/', $ticket ?? '')) return null;
    $f = muse_data_dir() . '/' . $ticket . '.json';
    if (!is_file($f)) return null;
    return json_decode(file_get_contents($f), true);
}

function save_ticket($ticket, $row) {
    file_put_contents(
        muse_data_dir() . '/' . $ticket . '.json',
        json_encode($row, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    );
}

// --- muse-protocol/1.1: canonical JSON, proof-of-work, signatures ---

// Canonical JSON: recursively sorted keys, no whitespace, non-ASCII escaped.
// Matches Python's json.dumps(obj, sort_keys=True, separators=(",", ":")).
// NOTE: PHP cannot distinguish {} from [] after json_decode(..., true), so an
// envelope containing an *empty object* will not canonicalize identically to
// the Python reference. The reference tools never emit empty objects; if you
// implement a sender, don't either.
function mp_canonical($v) {
    if (is_array($v)) {
        if (array_is_list($v)) {
            return '[' . implode(',', array_map('mp_canonical', $v)) . ']';
        }
        ksort($v, SORT_STRING);
        $parts = [];
        foreach ($v as $k => $val) {
            $parts[] = json_encode((string)$k, JSON_UNESCAPED_SLASHES) . ':'
                     . mp_canonical($val);
        }
        return '{' . implode(',', $parts) . '}';
    }
    // JSON_UNESCAPED_SLASHES: Python's json.dumps does not escape "/".
    // (Unicode stays escaped, matching Python's ensure_ascii default.)
    return json_encode($v, JSON_UNESCAPED_SLASHES);
}

// Bytes covered by the Ed25519 signature: the envelope minus sig/kid/pow.
function mp_sig_bytes($env) {
    $e = $env;
    unset($e['sig'], $e['kid'], $e['pow']);
    return mp_canonical($e);
}

// Bytes covered by the proof-of-work: the envelope minus pow.
function mp_pow_bytes($env) {
    $e = $env;
    unset($e['pow']);
    return mp_canonical($e);
}

function mp_leading_zero_bits($binary) {
    $n = 0;
    $len = strlen($binary);
    for ($i = 0; $i < $len; $i++) {
        $b = ord($binary[$i]);
        if ($b === 0) { $n += 8; continue; }
        for ($bit = 7; $bit >= 0; $bit--) {
            if (($b >> $bit) & 1) break 2;
            $n++;
        }
    }
    return $n;
}

// Verify the proof-of-work on an envelope. Returns the verified bit count
// (int) or false. Expects $env['pow'] = {"bits": N, "nonce": int}.
function mp_verify_pow($env) {
    $pow = $env['pow'] ?? null;
    if (!is_array($pow) || array_is_list($pow)) return false;
    $bits = $pow['bits'] ?? null;
    $nonce = $pow['nonce'] ?? null;
    if (!(is_int($bits) || (is_string($bits) && ctype_digit($bits)))) return false;
    if (!(is_int($nonce) || (is_string($nonce) && ctype_digit($nonce)))) return false;
    $bits = (int)$bits;
    $nonce = (int)$nonce;
    if ($bits < 1 || $bits > 64 || $nonce < 0) return false;
    $h = hash('sha256', mp_pow_bytes($env) . pack('J', $nonce), true);
    $got = mp_leading_zero_bits($h);
    return $got >= $bits ? $got : false;
}

// Verify an Ed25519 detached signature over the envelope. $sig_b64 and
// $pubkey_b64 are base64. Returns true/false.
function mp_verify_sig($env, $sig_b64, $pubkey_b64) {
    if (!function_exists('sodium_crypto_sign_verify_detached')) return false;
    if (!is_string($sig_b64) || !is_string($pubkey_b64)) return false;
    $sig = base64_decode($sig_b64, true);
    $pk  = base64_decode($pubkey_b64, true);
    if ($sig === false || $pk === false) return false;
    if (strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) return false;
    if (strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) return false;
    return sodium_crypto_sign_verify_detached($sig, mp_sig_bytes($env), $pk);
}

// Senders the Muse has approved: {"<key_id>": {"pubkey": "<base64>",
// "name": "...", "manifest_url": "...", "approved_at": "..."}}.
// Managed out-of-band by the Muse — the endpoint only reads it.
function mp_known_senders() {
    $f = muse_data_dir() . '/senders.json';
    if (!is_file($f)) return [];
    $d = json_decode(file_get_contents($f), true);
    return is_array($d) ? $d : [];
}
