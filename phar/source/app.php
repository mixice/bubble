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

// Resolve a writable real directory for room storage:
//   - web server runs the .phar directly  -> SCRIPT_FILENAME is the real .phar path
//   - bundled phar context                -> Phar::running() gives the real path
//   - fallback                            -> __DIR__ (read-only inside a phar)
$__bubbleBase = null;
$__sf = $_SERVER['SCRIPT_FILENAME'] ?? '';
if (strtolower(substr($__sf, -5)) === '.phar') {
    $__real = realpath($__sf);
    if ($__real) {
        $__bubbleBase = dirname($__real);
    }
}
if ($__bubbleBase === null && class_exists('Phar', false) && \Phar::running()) {
    $__bubbleBase = dirname(\Phar::running(false));
}
if ($__bubbleBase === null) {
    $__bubbleBase = __DIR__;
}
define('DATA_DIR',      $__bubbleBase . '/rooms');
define('PEER_TIMEOUT',  180);       // seconds without a heartbeat before a peer is considered gone
define('PEER_TOUCH_INTERVAL', 20);  // do not rewrite the room file for every poll
// Per-room ring buffer of message references. Attachments no longer live in the room
// file — only a small reference per file — so this caps chat turns, not raw bytes.
define('MAX_MSGS',      500);
define('MAX_PAYLOAD',   262144);    // 256 KB per JSON message (base64 ciphertext)
define('MAX_CHUNK',     1048576);   // 1 MB per raw attachment chunk
define('MIN_CHUNK',     4096);      // prevent tiny-chunk metadata / request amplification
define('MAX_PARTS',     16384);
define('SWEEP_INTERVAL', 30);       // seconds between full expiry sweeps
define('POLL_PAGE',      40);       // max messages returned per poll
define('BLOB_TTL',       21600);    // 6h: idle attachment blobs are reclaimed
define('MAX_BLOB',       52428800); // 50 MB hard cap per attachment
define('MAX_ROOM_BLOB_BYTES', 1073741824); // 1 GiB of committed + in-flight blobs per room
define('MAX_ROOM_FILES', 100);      // committed + in-flight attachments per room
define('UPLOAD_TTL',      21600);   // abandoned uploads are reclaimed after 6h
// Room self-compaction: keep the JSON small so every poll stays cheap and never
// exhausts memory. See compact_room() below.
define('COMPACT_CAP',    4 * 1048576);   // soft cap; above this we prune legacy leftovers
define('HARD_CAP',       16 * 1048576);  // only shed legit (non-legacy) messages past this
define('LEGACY_PAYLOAD', 256 * 1024);     // current clients are bounded below this; larger
                                          // entries are leftovers from the old inline-blob era

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
    // Require the complete identifier; silently stripping characters could make
    // two different attacker-supplied ids address the same file.
    if (!preg_match('/^[a-f0-9]{16,64}$/i', $fid)) {
        return '';
    }
    return blob_dir($room) . '/' . strtolower($fid) . '.bin';
}

function burned_path(string $room): string
{
    return DATA_DIR . '/' . hash('sha256', $room) . '.burned';
}

function valid_cid(string $cid): bool
{
    return $cid !== '' && preg_match('/^[a-f0-9]{12,64}$/i', $cid) === 1;
}

function valid_mid(string $mid): bool
{
    return $mid !== '' && preg_match('/^[a-f0-9]{8,64}$/i', $mid) === 1;
}

function room_blob_bytes(array $data): int
{
    $total = 0;
    foreach (['blobs', 'uploads'] as $bucket) {
        foreach (($data[$bucket] ?? []) as $item) {
            $total += max(0, (int) ($item['size'] ?? $item['bytes'] ?? 0));
        }
    }
    return $total;
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
        $lfp = null;
        if (!$orphan) {
            $lfp = @fopen($roomFile . '.lock', 'c+');
            if ($lfp === false || !@flock($lfp, LOCK_EX)) {
                if (is_resource($lfp)) fclose($lfp);
                continue;
            }
            // The room may have been burned between the initial is_file() check
            // and lock acquisition. Re-evaluate before touching its attachments.
            if (!is_file($roomFile)) {
                @flock($lfp, LOCK_UN);
                fclose($lfp);
                $lfp = null;
                $orphan = true;
            }
        }
        foreach (glob($dir . '/*.bin') ?: [] as $b) {
            $mtime = @filemtime($b);
            if ($orphan || $mtime === false || $now - $mtime > BLOB_TTL) {
                @unlink($b);
            }
        }
        if ($orphan) {
            @rmdir($dir);
        }
        if (is_resource($lfp)) {
            @flock($lfp, LOCK_UN);
            fclose($lfp);
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
 * @param bool $burned Mark a deliberately destroyed room so stale requests cannot recreate it.
 * @return array{0:array<string,mixed>|null,1:mixed}
 */
function transact(string $room, bool $create, ?string $cid, callable $fn, bool $burned = false): array
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

    if ($create && is_file(burned_path($room))) {
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        @unlink($lockp);
        return [null, ['burned' => true]];
    }

    if (!$create && !is_file($path)) {
        // Room file already gone (left / burned / expired). Keep the lock file in place:
        // unlinking it after releasing the handle would race a simultaneous create request.
        // It is tiny and can safely be reused by a later request.
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        return [null, null];
    }

    $raw  = is_file($path) ? @file_get_contents($path) : '';
    $data = ($raw === false || $raw === '') ? null : json_decode($raw, true);

    $now = time();
    $fresh = !is_array($data) || !isset($data['created'], $data['seq'], $data['msgs']);
    if ($fresh) {
        $data = ['created' => $now, 'seq' => 0, 'msgs' => [], 'peers' => [], 'uploads' => [], 'blobs' => []];
    } else {
        if (!is_array($data['peers'] ?? null)) {
            $data['peers'] = [];
        }
        if (!is_array($data['uploads'] ?? null)) {
            $data['uploads'] = [];
        }
        if (!is_array($data['blobs'] ?? null)) {
            $data['blobs'] = [];
        }
        foreach ($data['peers'] as $k => $ts) {
            if ($now - (int) $ts > PEER_TIMEOUT) {
                unset($data['peers'][$k]);
            }
        }
        foreach ($data['uploads'] as $fid => $upload) {
            $updated = (int) ($upload['updated'] ?? 0);
            if ($updated <= 0 || $now - $updated > UPLOAD_TTL || !is_file(blob_path($room, (string) $fid))) {
                @unlink(blob_path($room, (string) $fid));
                unset($data['uploads'][$fid]);
            }
        }
        foreach ($data['blobs'] as $fid => $blob) {
            if (!is_file(blob_path($room, (string) $fid))) {
                unset($data['blobs'][$fid]);
            }
        }
    }

    if ($cid !== null && $cid !== '' && valid_cid($cid)) {
        $last = isset($data['peers'][$cid]) ? (int) $data['peers'][$cid] : 0;
        if ($last === 0 || $now - $last >= PEER_TOUCH_INTERVAL) {
            $data['peers'][$cid] = $now;
        }
    }

    if (!$fresh && count($data['peers']) === 0 && !$burned) {
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
        if ($burned) {
            // Create the tombstone while the original lock is still linked. Any
            // stale create request that acquires the lock afterwards sees it first.
            @file_put_contents(burned_path($room), (string) time(), LOCK_EX);
        }
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
    // A heartbeat-only poll still needs to inspect the room under the lock, but it
    // should not rewrite identical JSON every few seconds. This is the main guard
    // against write amplification in busy rooms.
    if (is_string($raw) && hash_equals($raw, $json)) {
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        return [$data, $result];
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
 * reads it under the room lock, which is far too expensive on every single request
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
        // Exclusive lock on the same file transact() uses. The lock is held through
        // the liveness check and deletion so a heartbeat cannot race the unlink.
        $lfp = @fopen($lockp, 'c+');
        if ($lfp === false) {
            continue;
        }
        if (!@flock($lfp, LOCK_EX)) {
            fclose($lfp);
            continue;
        }
        $raw = is_file($file) ? @file_get_contents($file) : '';

        $data = ($raw === false || $raw === '') ? null : json_decode($raw, true);
        if (!is_array($data)) {
            // Unreadable snapshot (a mid-write race, or genuinely corrupt). NEVER
            // unlink on a parse failure — a concurrent writer may simply be in
            // flight. Re-evaluate on a later request.
            @flock($lfp, LOCK_UN);
            fclose($lfp);
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
        @flock($lfp, LOCK_UN);
        fclose($lfp);
        if (!$alive) {
            @unlink($file . '.lock');
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
$action  = (string) ($_GET['a'] ?? '');
$contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($action === 'fpart' && $contentLength > MAX_CHUNK) {
    out(['error' => 'chunk too large'], 413);
}
if ($action === '' && $contentLength > MAX_PAYLOAD + 8192) {
    out(['error' => 'request too large'], 413);
}
$rawBody = (string) file_get_contents('php://input');

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

$requestCid = (string) ($body['cid'] ?? '');
if ($requestCid !== '' && !valid_cid($requestCid)) {
    out(['error' => 'bad cid'], 400);
}

sweep_expired();

switch ($action) {

    case 'hello':
        $cid = (string) ($body['cid'] ?? '');
        if (!valid_cid($cid)) {
            out(['error' => 'bad cid'], 400);
        }
        [$data, $info] = transact($room, true, $cid, function (array &$data): array {
            return [
                'seq' => $data['seq'],
            ];
        });
        if ($data === null) {
            out(['gone' => true], 410);
        }
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
        $mid = (string) ($body['mid'] ?? '');
        if (!valid_cid($cid) || ($mid !== '' && !valid_mid($mid))) {
            out(['error' => 'bad message id'], 400);
        }
        [$data, $seq] = transact($room, true, $cid, function (array &$data) use ($payload, $mid): int {
            if ($mid !== '') {
                foreach ($data['msgs'] as $existing) {
                    if (is_array($existing) && ($existing['m'] ?? '') === $mid) {
                        return (int) ($existing['i'] ?? 0);
                    }
                }
            }
            $data['seq']++;
            $message = ['i' => $data['seq'], 't' => time(), 'p' => $payload];
            if ($mid !== '') {
                $message['m'] = $mid;
            }
            $data['msgs'][] = $message;
            return $data['seq'];
        });
        if ($data === null) {
            out(['gone' => true], 410);
        }
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

    case 'leave':
        // A peer is leaving: drop only this cid from the presence set. We pass cid=null
        // so transact() does NOT re-stamp us, then remove ourselves in the callback.
        // If nobody else remains, $data is nulled to purge the room immediately.
        $cid = (string) ($body['cid'] ?? '');
        if (!valid_cid($cid)) {
            out(['error' => 'bad cid'], 400);
        }
        transact($room, false, null, function (array &$data) use ($cid): void {
            unset($data['peers'][$cid]);
            if (count($data['peers']) === 0) {
                $data = null; // last one out — destroy the room now
            }
        });
        out(['ok' => true]);

    case 'clear':
        // Wipe messages for the whole room (every online peer sees an empty room on next poll).
        // Peers are kept so the room stays alive while someone is still watching.
        $cid = (string) ($body['cid'] ?? '');
        if (!valid_cid($cid)) {
            out(['error' => 'bad cid'], 400);
        }
        [$data] = transact($room, false, $cid, function (array &$data) use ($room): void {
            $data['seq']   = 0;
            $data['msgs']  = [];
            $data['uploads'] = [];
            $data['blobs'] = [];
            // Hold the room lock while purging files so an in-flight fpart cannot
            // append data after a clear operation has completed.
            purge_dir(blob_dir($room));
        });
        if ($data === null) {
            out(['gone' => true], 410);
        }
        out(['ok' => true]);

    case 'fbegin':
        // Reserve a slot for an encrypted attachment: bytes stream into a standalone
        // blob, the room JSON only ever carries a tiny reference message.
        $fid  = (string) ($body['fid'] ?? '');
        $cid  = (string) ($body['cid'] ?? '');
        $size = (int) ($body['size'] ?? 0);
        if (($body['probe'] ?? '') === '1') {
            if (!valid_cid($cid)) {
                out(['error' => 'bad cid'], 400);
            }
            [$data, $info] = transact($room, false, $cid, function (array &$data): array {
                return ['chunk' => max(65536, min(php_bytes((string) ini_get('post_max_size')), MAX_CHUNK) - 8192)];
            });
            if ($data === null) {
                out(['gone' => true], 410);
            }
            out(['ok' => true, 'chunk' => $info['chunk']]);
        }
        $path = blob_path($room, $fid);
        if ($path === '' || !valid_cid($cid) || $size <= 0 || $size > MAX_BLOB) {
            out(['error' => 'bad upload'], 400);
        }
        [$data, $info] = transact($room, false, $cid, function (array &$data) use ($room, $fid, $cid, $size, $path): array {
            if (isset($data['uploads'][$fid]) || isset($data['blobs'][$fid])) {
                return ['error' => 'upload exists'];
            }
            if (count($data['uploads']) + count($data['blobs']) >= MAX_ROOM_FILES || room_blob_bytes($data) + $size > MAX_ROOM_BLOB_BYTES) {
                return ['error' => 'room quota exceeded'];
            }
            $dir = dirname($path);
            if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
                return ['error' => 'storage unavailable'];
            }
            // 'wb' truncates, so retrying with the same fid starts from a clean slate.
            $fp = @fopen($path, 'wb');
            if ($fp === false) {
                return ['error' => 'storage unavailable'];
            }
            fclose($fp);
            $data['uploads'][$fid] = [
                'cid' => $cid,
                'size' => $size,
                'bytes' => 0,
                'next' => 0,
                'chunk' => max(65536, min(php_bytes((string) ini_get('post_max_size')), MAX_CHUNK) - 8192),
                'updated' => time(),
                'parts' => [],
            ];
            return ['chunk' => $data['uploads'][$fid]['chunk']];
        });
        if ($data === null) {
            out(['gone' => true], 410);
        }
        if (isset($info['error'])) {
            out(['error' => $info['error']], $info['error'] === 'room quota exceeded' ? 413 : 409);
        }
        out([
            'ok'    => true,
            'chunk' => $info['chunk'],
        ]);

    case 'fpart':
        // Body is raw ciphertext: append it verbatim. No base64, no JSON envelope,
        // and crucially nothing lands in the room file.
        $fid  = (string) ($body['fid'] ?? '');
        $cid  = (string) ($body['cid'] ?? '');
        $seq  = (int) ($body['seq'] ?? -1);
        $path = blob_path($room, $fid);
        if ($path === '' || !valid_cid($cid) || $seq < 0) {
            out(['error' => 'bad upload'], 400);
        }
        if (strlen($rawBody) === 0 || strlen($rawBody) > MAX_CHUNK) {
            out(['error' => 'bad chunk'], 400);
        }
        [$data, $info] = transact($room, false, $cid, function (array &$data) use ($fid, $cid, $seq, $rawBody, $path): array {
            $upload = $data['uploads'][$fid] ?? null;
            if (!is_array($upload) || ($upload['cid'] ?? '') !== $cid || !is_file($path)) {
                return ['error' => 'no slot'];
            }
            $next = (int) ($upload['next'] ?? 0);
            $bytes = (int) ($upload['bytes'] ?? 0);
            $length = strlen($rawBody);
            if ($length < MIN_CHUNK && $bytes + $length < (int) ($upload['size'] ?? 0)) {
                return ['error' => 'chunk too small'];
            }
            if ($next >= MAX_PARTS) {
                return ['error' => 'too many chunks'];
            }
            if ($seq < $next) {
                $part = $upload['parts'][(string) $seq] ?? null;
                $offset = is_array($part) ? (int) ($part['offset'] ?? -1) : -1;
                $partLength = is_array($part) ? (int) ($part['length'] ?? -1) : -1;
                if ($offset < 0 || $partLength !== $length || $offset + $partLength > $bytes) {
                    return ['error' => 'duplicate chunk mismatch'];
                }
                $fp = @fopen($path, 'rb');
                if ($fp === false || fseek($fp, $offset) !== 0) {
                    @fclose($fp);
                    return ['error' => 'storage read failed'];
                }
                $old = fread($fp, $length);
                fclose($fp);
                $expectedHash = is_array($part) ? (string) ($part['hash'] ?? '') : '';
                if (!is_string($old) || $expectedHash === '' || !hash_equals($expectedHash, hash('sha256', $rawBody))) {
                    return ['error' => 'duplicate chunk mismatch'];
                }
                return ['ok' => true, 'duplicate' => true];
            }
            if ($seq !== $next || $bytes !== (int) @filesize($path)) {
                return ['error' => 'out of order', 'expected' => $next];
            }
            if ($bytes + strlen($rawBody) > (int) ($upload['size'] ?? 0) || $bytes + strlen($rawBody) > MAX_BLOB) {
                return ['error' => 'attachment too large'];
            }
            if (@file_put_contents($path, $rawBody, FILE_APPEND | LOCK_EX) === false) {
                return ['error' => 'storage write failed'];
            }
            $data['uploads'][$fid]['bytes'] = $bytes + strlen($rawBody);
            $data['uploads'][$fid]['next'] = $next + 1;
            $data['uploads'][$fid]['updated'] = time();
            $data['uploads'][$fid]['parts'][(string) $seq] = [
                'offset' => $bytes,
                'length' => strlen($rawBody),
                'hash' => hash('sha256', $rawBody),
            ];
            return ['ok' => true];
        });
        if ($data === null) {
            out(['gone' => true], 410);
        }
        if (($info['error'] ?? '') !== '') {
            out($info, ($info['error'] === 'out of order' || $info['error'] === 'no slot') ? 409 : 400);
        }
        out(['ok' => true]);

    case 'fcommit':
        $fid = (string) ($body['fid'] ?? '');
        $cid = (string) ($body['cid'] ?? '');
        $path = blob_path($room, $fid);
        if ($path === '' || !valid_cid($cid)) {
            out(['error' => 'bad upload'], 400);
        }
        [$data, $info] = transact($room, false, $cid, function (array &$data) use ($fid, $cid, $path): array {
            $upload = $data['uploads'][$fid] ?? null;
            if (!is_array($upload) || ($upload['cid'] ?? '') !== $cid || !is_file($path)) {
                return ['error' => 'no slot'];
            }
            $size = (int) ($upload['size'] ?? 0);
            $bytes = (int) ($upload['bytes'] ?? 0);
            if ($bytes !== $size || (int) @filesize($path) !== $size) {
                return ['error' => 'upload incomplete'];
            }
            $data['blobs'][$fid] = [
                'cid' => $cid,
                'size' => $size,
                'updated' => time(),
            ];
            unset($data['uploads'][$fid]);
            return ['ok' => true];
        });
        if ($data === null) {
            out(['gone' => true], 410);
        }
        if (($info['error'] ?? '') !== '') {
            out($info, $info['error'] === 'no slot' ? 409 : 400);
        }
        out(['ok' => true]);

    case 'fetch':
        $fid  = (string) ($body['fid'] ?? '');
        $cid  = (string) ($body['cid'] ?? '');
        $path = blob_path($room, $fid);
        if ($path === '' || !valid_cid($cid)) {
            out(['error' => 'bad request'], 400);
        }
        [$data, $info] = transact($room, false, $cid, function (array &$data) use ($fid, $path, $cid): array {
            // Older rooms predate the blob manifest. Keep their already-written
            // attachments readable while new uploads remain manifest-controlled.
            if (!is_file($path) || (isset($data['blobs'][$fid]) === false && isset($data['uploads'][$fid]))) {
                return ['error' => 'not found'];
            }
            if (!isset($data['blobs'][$fid])) {
                $data['blobs'][$fid] = ['cid' => '', 'size' => (int) @filesize($path), 'updated' => time()];
            }
            // Refresh mtime so a blob people are still pulling is never reaped.
            @touch($path);
            return ['ok' => true, 'size' => (int) @filesize($path)];
        });
        if ($data === null) {
            out(['gone' => true], 410);
        }
        if (($info['error'] ?? '') !== '') {
            out(['error' => $info['error']], 404);
        }
        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . (string) $info['size']);
        @readfile($path);
        exit;

    case 'burn':
        // Destroy the whole room. Route through transact() so we reuse the SAME
        // purge path that deletes the room JSON AND its .lock AND the blob dir —
        // the old standalone unlink left an orphan .lock on disk forever. Passing
        // cid=null avoids re-stamping a presence entry we're about to erase.
        transact($room, false, null, function (array &$data): void {
            $data = null; // unconditional purge regardless of who else is in the room
        }, true);
        out(['ok' => true]);

    default:
        out(['error' => 'unknown action'], 400);
}
