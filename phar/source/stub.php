<?php
// Bubble chat — single-file phar web app entry point.
// Serves the front-end, static assets, and routes every POST to the bundled
// zero-knowledge relay (app.php). The room data and ciphertext never leave the
// client unencrypted; see app.php for the server-side contract.
Phar::mapPhar('bubble.phar');

// Discourage search engines / crawlers from indexing this private chat instance.
// Sent on every response leaving this front controller (HTML, assets, API, 404).
header('X-Robots-Tag: noindex, nofollow');

// All bundled assets are served through the phar://bubble.phar stream. The alias is
// registered by Phar::mapPhar('bubble.phar') above, so this works whether the .phar is
// executed directly (web entry point) or merely included by a dev router.
$root = 'phar://bubble.phar';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$rel = ltrim($uri, '/');

$STATIC = [
    'css'  => 'text/css; charset=utf-8',
    'js'   => 'application/javascript; charset=utf-8',
    'mjs'  => 'application/javascript; charset=utf-8',
    'svg'  => 'image/svg+xml',
    'jpg'  => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png'  => 'image/png',
    'gif'  => 'image/gif',
    'webp' => 'image/webp',
    'ico'  => 'image/x-icon',
    'mp3'  => 'audio/mpeg',
    'wav'  => 'audio/wav',
    'woff' => 'font/woff',
    'woff2'=> 'font/woff2',
    'ttf'  => 'font/ttf',
    'json' => 'application/json',
];

// Every POST is an API call — chat.js always posts to location.pathname.
if ($method === 'POST') {
    require $root . '/app.php';
    exit;
}

// Serve /robots.txt from the phar itself so well-behaved crawlers are told not to
// index anything. Handled here so it works regardless of how the web server routes
// requests (the phar is the only entry point; a missing physical file would otherwise
// fall through to the index.html shell).
if ($rel === 'robots.txt') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "User-agent: *\nDisallow: /\n";
    exit;
}

// Guard against path traversal inside the archive.
if (strpos($rel, '..') !== false || strpos($rel, '\\') !== false) {
    http_response_code(400);
    echo 'Bad request';
    exit;
}

$self = basename($rel);
$ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
$file = $root . '/' . $rel;

if ($rel !== '' && $self !== 'bubble.phar' && isset($STATIC[$ext]) && is_file($file)) {
    header('Content-Type: ' . $STATIC[$ext]);
    header('Cache-Control: public, max-age=3600');
    header('X-Content-Type-Options: nosniff');
    readfile($file);
    exit;
}

// Front controller: serve the chat UI for any other GET (incl. "/" or "/bubble.phar").
if (is_file($root . '/index.html')) {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    readfile($root . '/index.html');
    exit;
}

http_response_code(404);
echo 'Bubble: index.html not found in archive';
__HALT_COMPILER();
