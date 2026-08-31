<?php
declare(strict_types=1);

// Rooms created by the old architecture inlined base64 file chunks, so a busy room's
// JSON could grow past 50 MB. Decoding that on every poll blew past the default 128M
// limit and crashed the whole request (which the client saw as a frozen, dead chat).
// Give ourselves headroom to decode + compact those legacy rooms on first access.
@ini_set('memory_limit', '1024M');

/**
 * api.php — zero-dependency relay for eph-chat (PHP edition)
 *
 * Ground rules, do not break them:
 *   1. No extensions, no composer, no database. Rooms are JSON files under DATA_DIR.
 *   2. Payloads are opaque base64 strings. This file never parses or decrypts them.
 *   3. The password never reaches the server. Only the room name is sent, and it
 *      is only used as a bucket key — content stays unreadable without the password.
 *   4. A room is destroyed when no peer has sent a heartbeat within PEER_TIMEOUT.
 *      Clearing wipes messages for everyone in the room; it does NOT evict peers.
 *   5. Nothing is logged.
 */

define('DATA_DIR',      __DIR__ . '/rooms');
define('PEER_TIMEOUT',  180);       // seconds without a heartbeat before a peer is considered gone
// Per-room ring buffer of message references. Attachments no longer live in the room
// file — only a small reference per file — so this caps chat turns, not raw bytes.
define('MAX_MSGS',      500);
define('MAX_PAYLOAD',   1048576);   // 1 MB per message (base64 ciphertext)
define('SWEEP_INTERVAL', 30);       // seconds between full expiry sweeps
define('POLL_PAGE',      40);       // max messages returned per poll
define('BLOB_TTL',       21600);    // 6h: idle attachment blobs are reclaimed
define('MAX_BLOB',       52428800); // 50 MB hard cap per attachment
// Room self-compaction: keep the JSON small so every poll stays cheap and never
// exhausts memory. See compact_room() below.
define('COMPACT_CAP',    4 * 1048576);   // soft cap; above this we prune legacy leftovers
define('HARD_CAP',       16 * 1048576);  // only shed legit (non-legacy) messages past this
define('LEGACY_PAYLOAD', 64 * 1024);     // payloads above this are leftover inline blobs from
                                          // the old base64-chunk era — unreadable today, safe to drop

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet');
header('X-Content-Type-Options: nosniff');

/** @return never */
function out(array $payload, int $code = 200): void
{
    http_response_code($code);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Parse a php.ini size string ("2M", "512K", "1G", "1024") into bytes.
 */
function php_bytes(string $v): int
{
    $v = trim($v);
    if ($v === '') return 0;
    $n = (int) $v;
    $u = strtolower($v[-1] ?? '');
    switch ($u) {
        case 'g': $n *= 1024;
        case 'm': $n *= 1024;
        case 'k': $n *= 1024;
    }
    return $n;
}

function room_path(string $room): string
{
    // Bucket key is a hash, so a hostile room name can never touch the filesystem.
    return DATA_DIR . '/' . hash('sha256', $room) . '.json';
}

function blob_dir(string $room): string
{
    return DATA_DIR . '/' . hash('sha256', $room) . '.files';
}

function blob_path(string $room, string $fid): string
{
    // Keep hex only, so a hand-crafted fid can never walk out of the directory.
    $safe = preg_replace('/[^a-f0-9]/i', '', $fid) ?: '';
    return $safe === '' ? '' : blob_dir($room) . '/' . strtolower($safe) . '.bin';
}

function purge_dir(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    foreach (glob($dir . '/*') ?: [] as $f) {
        if (is_file($f)) {
            @unlink($f);
        }
    }
    @rmdir($dir);
}

/**
 * Keep the room file small. Messages now carry only tiny envelopes — a few hundred
 * bytes of text, or a reference to an external blob — so a healthy room is well under
 * a megabyte. Rooms from the old architecture inlined base64 file chunks (each payload
 * up to ~1 MB), ballooning the JSON and making every poll exhaust PHP memory.
 *
 * Anything over LEGACY_PAYLOAD can only be such a leftover: the current client cannot
 * decrypt it (different envelope), so it is safe to drop. We shed the OLDEST legacy
 * messages first, ring-buffer style, until under the soft cap. Only if the room is
 * STILL oversized after that — purely from very long texts — do we drop the oldest
 * messages regardless, which is acceptable ring-buffer behaviour.
 */
function compact_room(array $data): array
{
    $msgs = isset($data['msgs']) && is_array($data['msgs']) ? array_values($data['msgs']) : [];
    $size = 0;
    foreach ($msgs as $m) {
        $size += strlen(is_array($m) ? (string) ($m['p'] ?? '') : '') + 48;
    }
    if ($size <= COMPACT_CAP) {
        $data['msgs'] = $msgs;
        return $data;
    }

    // Pass 1: drop the oldest legacy (oversized) messages until under the soft cap.
    while ($size > COMPACT_CAP) {
        $dropped = false;
        foreach ($msgs as $k => $m) {
            $len = strlen(is_array($m) ? (string) ($m['p'] ?? '') : '');
            if ($len > LEGACY_PAYLOAD) {
                $size -= ($len + 48);
                unset($msgs[$k]);
                $dropped = true;
                break; // re-scan from the front for the next oldest
            }
        }
        if (!$dropped) {
            break; // no legacy messages left to prune
        }
    }
    $msgs = array_values($msgs);

    // Pass 2: still too big? shed the oldest messages regardless (ring buffer).
    while ($size > HARD_CAP && count($msgs) > 0) {
        $m = array_shift($msgs);
        $size -= (strlen(is_array($m) ? (string) ($m['p'] ?? '') : '') + 48);
    }

    $data['msgs'] = array_values($msgs);
    return $data;
}

/**
 * Reclaim attachment blobs: expired ones, plus any directory whose room is gone.
 * fetch() refreshes mtime, so blobs people still download are never reaped.
 */
function sweep_blobs(): void
{
    if (!is_dir(DATA_DIR)) {
        return;
    }
    $now = time();
    foreach (glob(DATA_DIR . '/*.files') ?: [] as $dir) {
        if (!is_dir($dir)) {
            continue;
        }
        $roomFile = preg_replace('/\.files$/', '.json', (string) $dir) ?: '';
        $orphan   = $roomFile === '' || !is_file($roomFile);
        foreach (glob($dir . '/*.bin') ?: [] as $b) {
            $mtime = @filemtime($b);
            if ($orphan || $mtime === false || $now - $mtime > BLOB_TTL) {
                @unlink($b);
            }
        }
        if ($orphan) {
            @rmdir($dir);
        }
    }
}

/**
 * Open a room under an exclusive lock, hand it to $fn, write it back.
 * If $fn sets $data to null the room file is deleted.
 *
 * $cid is the caller's peer id; it is (re)stamped as "alive" on every request.
 * Peers whose last heartbeat is older than PEER_TIMEOUT are dropped first, so a
 * room with zero live peers is purged (after the grace window) instead of lingering.
 *
 * @param callable(array<string,mixed>):mixed $fn
 * @return array{0:array<string,mixed>|null,1:mixed}
 */
function transact(string $room, bool $create, ?string $cid, callable $fn): array
{
    if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0700, true) && !is_dir(DATA_DIR)) {
        out(['error' => 'storage unavailable'], 500);
    }

    $path  = room_path($room);
    $lockp = $path . '.lock';
    // Use a SEPARATE lock file (not the room file) so we can freely rename()/unlink()
    // the room file while holding the lock — a direct lock on the room file would block
    // unlink() on Windows (open handle) and is fragile.
    $lfp = @fopen($lockp, 'c+');
    if ($lfp === false) {
        out(['error' => 'storage unavailable'], 500);
    }
    @flock($lfp, LOCK_EX);

    if (!$create && !is_file($path)) {
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        return [null, null];
    }

    $raw  = is_file($path) ? @file_get_contents($path) : '';
    $data = ($raw === false || $raw === '') ? null : json_decode($raw, true);

    $now = time();
    $fresh = !is_array($data) || !isset($data['created'], $data['seq'], $data['msgs']);
    if ($fresh) {
        $data = ['created' => $now, 'seq' => 0, 'msgs' => [], 'peers' => []];
    } else {
        if (!is_array($data['peers'] ?? null)) {
            $data['peers'] = [];
        }
        foreach ($data['peers'] as $k => $ts) {
            if ($now - (int) $ts > PEER_TIMEOUT) {
                unset($data['peers'][$k]);
            }
        }
    }

    if ($cid !== null && $cid !== '') {
        $data['peers'][$cid] = $now;
    }

    if (!$fresh && count($data['peers']) === 0) {
        @unlink($path);
        purge_dir(blob_dir($room));
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        return [null, null];
    }

    // Shrink oversized rooms (typically legacy inline-blob leftovers) so polls stay
    // cheap and never exhaust PHP memory. Must run BEFORE $fn so poll returns the
    // already-trimmed message set instead of a multi-megabyte slab of dead weight.
    $data = compact_room($data);

    $result = $fn($data);

    if ($data === null) {
        @unlink($path);
        purge_dir(blob_dir($room));
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        return [null, $result];
    }

    if (count($data['msgs']) > MAX_MSGS) {
        $data['msgs'] = array_slice($data['msgs'], -MAX_MSGS);
    }
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    // NEVER persist a failed encoding. json_encode() returns false (cast to "") when
    // the room outgrows available memory; writing that blanks the file, and the next
    // read rebuilds the room from scratch with seq = 0 — which every client renders as
    // "chat history has been cleared". Keep the previous file and report the failure.
    if (!is_string($json) || $json === '') {
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        out(['error' => 'storage encode failed'], 500);
    }
    // Atomic write: stage to a temp file, then rename() into place. On POSIX the
    // rename is atomic (readers see old or new, never half); on Windows rename() won't
    // overwrite, so we fall back to unlink()+rename() below.
    $tmp = $path . '.' . getmypid() . '.' . mt_rand(1, 9999999) . '.tmp';
    $tf  = @fopen($tmp, 'w');
    if ($tf === false || @fwrite($tf, $json) === false) {
        @fclose($tf);
        @unlink($tmp);
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        out(['error' => 'storage write failed'], 500);
    }
    fflush($tf);
    fclose($tf);
    if (!@rename($tmp, $path)) {
        @unlink($path);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            @flock($lfp, LOCK_UN);
            fclose($lfp);
            out(['error' => 'storage write failed'], 500);
        }
    }
    @flock($lfp, LOCK_UN);
    fclose($lfp);

    return [$data, $result];
}

/**
 * Remove rooms that have zero live peers.
 *
 * Throttled to at most one pass per SWEEP_INTERVAL: a full sweep globs every room and
 * reads it under a shared lock, which is far too expensive on every single request
 * once a room holds tens of megabytes of file chunks. The delay only shifts room
 * reclamation by SWEEP_INTERVAL past PEER_TIMEOUT, which is harmless.
 */
function sweep_expired(): void
{
    if (!is_dir(DATA_DIR)) {
        return;
    }
    $stamp = DATA_DIR . '/.sweep';
    $now   = time();
    $sraw  = @file_get_contents($stamp);
    $last  = ($sraw === false || $sraw === '') ? 0 : (int) $sraw;
    if ($last > 0 && $now - $last < SWEEP_INTERVAL) {
        return;
    }
    // Stamp before scanning so concurrent requests do not all pile into one sweep.
    @file_put_contents($stamp, (string) $now, LOCK_EX);

    sweep_blobs();

    $glob = glob(DATA_DIR . '/*.json');
    foreach ($glob === false ? [] : $glob as $file) {
        $lockp = $file . '.lock';
        // SHARED lock on the same file transact() uses, so we never read mid-rename().
        // Without it a racing write could hand us a truncated JSON.
        $lfp = @fopen($lockp, 'c+');
        if ($lfp === false) {
            continue;
        }
        if (!@flock($lfp, LOCK_SH)) {
            fclose($lfp);
            continue;
        }
        $raw = is_file($file) ? @file_get_contents($file) : '';
        @flock($lfp, LOCK_UN);
        fclose($lfp);

        $data = ($raw === false || $raw === '') ? null : json_decode($raw, true);
        if (!is_array($data)) {
            // Unreadable snapshot (a mid-write race, or genuinely corrupt). NEVER
            // unlink on a parse failure — a concurrent writer may simply be in
            // flight. Re-evaluate on a later request.
            continue;
        }
        $peers = is_array($data['peers'] ?? null) ? $data['peers'] : [];
        $alive = false;
        foreach ($peers as $ts) {
            if ($now - (int) $ts <= PEER_TIMEOUT) {
                $alive = true;
                break;
            }
        }
        if (!$alive) {
            @unlink($file);
            purge_dir(preg_replace('/\.json$/', '.files', $file) ?: '');
        }
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    out(['error' => 'POST only'], 405);
}

// Two request flavours:
//   * JSON API   — the action lives in the JSON body (default).
//   * raw binary — the action lives in the query string and the body is opaque
//                  ciphertext bytes. That is how attachments travel now: base64-encoding
//                  them into the room JSON is what blew up PHP's memory limit before.
$rawBody = (string) file_get_contents('php://input');
$action  = (string) ($_GET['a'] ?? '');

if ($action === '') {
    $body = json_decode($rawBody, true);
    if (!is_array($body)) {
        out(['error' => 'bad json'], 400);
    }
    $action = (string) ($body['a'] ?? '');
} else {
    $body = $_GET;
}

$room = (string) ($body['room'] ?? '');
if (!preg_match('/^[A-Za-z0-9_\-\x{4e00}-\x{9fa5}]{1,32}$/u', $room)) {
    out(['error' => 'bad room'], 400);
}

sweep_expired();

switch ($action) {

    case 'hello':
        $cid = (string) ($body['cid'] ?? '');
        [$data, $info] = transact($room, true, $cid, function (array &$data): array {
            return [
                'seq' => $data['seq'],
            ];
        });
        // Max single-request body = min(php post_max_size, server MAX_PAYLOAD).
        // The client shrinks its chunk below this so no block exceeds the limit.
        // If nginx client_max_body_size is stricter, ops must raise it to match.
        $maxBody = min(php_bytes((string) ini_get('post_max_size')), MAX_PAYLOAD);
        out([
            'ok'     => true,
            'seq'    => $info['seq'],
            'limit'  => $maxBody,
            'online' => count($data['peers'] ?? []),
        ]);

    case 'post':
        $payload = (string) ($body['payload'] ?? '');
        if ($payload === '' || strlen($payload) > MAX_PAYLOAD) {
            out(['error' => 'bad payload'], 400);
        }
        $cid = (string) ($body['cid'] ?? '');
        [$data, $seq] = transact($room, true, $cid, function (array &$data) use ($payload): int {
            $data['seq']++;
            $data['msgs'][] = ['i' => $data['seq'], 't' => time(), 'p' => $payload];
            return $data['seq'];
        });
        out([
            'ok' => true,
            'i'  => $seq,
        ]);

    case 'poll':
        $since = (int) ($body['since'] ?? 0);
        $limit = (int) ($body['limit'] ?? 0);
        $cid   = (string) ($body['cid'] ?? '');
        // Bounded page. Dumping an entire multi-megabyte room in one response is what
        // made rejoining a busy room hang for ages with a frozen UI.
        if ($limit <= 0 || $limit > POLL_PAGE) {
            $limit = POLL_PAGE;
        }
        [$data, $page] = transact($room, false, $cid, function (array &$data) use ($since, $limit): array {
            $fresh = [];
            $more  = false;
            foreach ($data['msgs'] as $msg) {
                if ((int) $msg['i'] <= $since) {
                    continue;
                }
                if (count($fresh) >= $limit) {
                    $more = true;
                    break;
                }
                $fresh[] = $msg;
            }
            return ['msgs' => $fresh, 'more' => $more];
        });
        if ($data === null) {
            out(['gone' => true]);
        }
        out([
            'msgs'   => $page['msgs'],
            'more'   => $page['more'],
            'seq'    => $data['seq'],
            'online' => count($data['peers'] ?? []),
        ]);

    case 'clear':
        // Wipe messages for the whole room (every online peer sees an empty room on next poll).
        // Peers are kept so the room stays alive while someone is still watching.
        $cid = (string) ($body['cid'] ?? '');
        transact($room, false, $cid, function (array &$data): void {
            $data['seq']   = 0;
            $data['msgs']  = [];
        });
        purge_dir(blob_dir($room));
        out(['ok' => true]);

    case 'fbegin':
        // Reserve a slot for an encrypted attachment: bytes stream into a standalone
        // blob, the room JSON only ever carries a tiny reference message.
        $fid  = (string) ($body['fid'] ?? '');
        $path = blob_path($room, $fid);
        if ($path === '') {
            out(['error' => 'bad fid'], 400);
        }
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            out(['error' => 'storage unavailable'], 500);
        }
        // 'wb' truncates, so retrying with the same fid starts from a clean slate.
        $fp = @fopen($path, 'wb');
        if ($fp === false) {
            out(['error' => 'storage unavailable'], 500);
        }
        fclose($fp);
        out([
            'ok'    => true,
            'chunk' => max(65536, min(php_bytes((string) ini_get('post_max_size')), MAX_PAYLOAD) - 8192),
        ]);

    case 'fpart':
        // Body is raw ciphertext: append it verbatim. No base64, no JSON envelope,
        // and crucially nothing lands in the room file.
        $fid  = (string) ($body['fid'] ?? '');
        $path = blob_path($room, $fid);
        if ($path === '' || !is_file($path)) {
            out(['error' => 'no slot'], 400);
        }
        if (strlen($rawBody) === 0 || strlen($rawBody) > MAX_PAYLOAD) {
            out(['error' => 'bad chunk'], 400);
        }
        if (@file_put_contents($path, $rawBody, FILE_APPEND | LOCK_EX) === false) {
            out(['error' => 'storage write failed'], 500);
        }
        clearstatcache(true, $path);
        if ((int) @filesize($path) > MAX_BLOB) {
            @unlink($path);
            out(['error' => 'attachment too large'], 400);
        }
        out(['ok' => true]);

    case 'fetch':
        $fid  = (string) ($body['fid'] ?? '');
        $path = blob_path($room, $fid);
        if ($path === '' || !is_file($path)) {
            out(['error' => 'not found'], 404);
        }
        // Refresh mtime so a blob people are still pulling is never reaped.
        @touch($path);
        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . (string) (int) @filesize($path));
        @readfile($path);
        exit;

    case 'burn':
        @unlink(room_path($room));
        purge_dir(blob_dir($room));
        out(['ok' => true]);

    default:
        out(['error' => 'unknown action'], 400);
}
