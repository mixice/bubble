<?php
// Build bubble.phar from the phar/ directory.
// Usage: php -d phar.readonly=0 build_phar.php
$pharFile = __DIR__ . '/bubble.phar';
if (file_exists($pharFile)) {
    unlink($pharFile);
}

$phar = new Phar($pharFile, 0, 'bubble.phar');
$phar->startBuffering();

// Map archive-internal name => source file on disk.
$map = [
    'index.html' => 'source/index.html',
    'app.php'    => 'source/app.php',
    'chat.css'   => 'source/chat.css',
    'chat.js'    => 'source/chat.js',
    'ico.svg'    => 'source/ico.svg',
    'send.mp3'   => 'source/send.mp3',
    'receive.mp3'=> 'source/receive.mp3',
    'end.mp3'    => 'source/end.mp3',
    'delete.mp3' => 'source/delete.mp3',
];
foreach ($map as $local => $src) {
    $srcPath = __DIR__ . '/' . $src;
    if (!is_file($srcPath)) {
        fwrite(STDERR, "missing source: $srcPath\n");
        exit(1);
    }
    $phar->addFile($srcPath, $local);
}

$stubPath = __DIR__ . '/source/stub.php';
$stub = file_get_contents($stubPath);
if ($stub === false) {
    fwrite(STDERR, "missing stub: $stubPath\n");
    exit(1);
}
// Make sure the stub terminates EXACTLY with __HALT_COMPILER(); and nothing after it.
$stub = rtrim($stub, "\r\n");
if (substr($stub, -19) !== '__HALT_COMPILER();') {
    $stub .= "\n__HALT_COMPILER();";
}
$phar->setStub($stub);
$phar->stopBuffering();

echo 'Built ' . $pharFile . ' (' . filesize($pharFile) . " bytes)\n";
