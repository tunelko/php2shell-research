<?php
declare(strict_types=1);

/**
 * PHP front controller for the challenge platform.
 *
 * This platform service runs patched PHP. It only publishes documentation,
 * status metadata, and the player bundle. The intentionally vulnerable PHP
 * runtime is a separate Docker service.
 */

const DEFAULT_TARGET = 'http://127.0.0.1:8426';

function respond_json(array $value, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function request_path(): string
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    return is_string($path) ? $path : '/';
}

function environment(string $name, string $default): string
{
    $value = getenv($name);
    return is_string($value) && $value !== '' ? rtrim($value, '/') : $default;
}

function runtime_status(string $url): array
{
    $started = microtime(true);
    $context = stream_context_create([
        'http' => [
            'timeout' => 2.0,
            'ignore_errors' => true,
            'method' => 'GET',
            'user_agent' => 'PHP2Shell-Platform/1.0',
        ],
    ]);

    $body = @file_get_contents($url, false, $context);
    if ($body === false) {
        return [
            'reachable' => false,
            'latency_ms' => round((microtime(true) - $started) * 1000, 2),
        ];
    }

    $status = 0;
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d+)/', $header, $matches) === 1) {
            $status = (int) $matches[1];
        }
    }

    $values = [];
    foreach (explode("\n", $body) as $line) {
        if (str_contains($line, '=')) {
            [$key, $value] = explode('=', $line, 2);
            $values[trim($key)] = trim($value);
        }
    }

    return [
        'reachable' => $status >= 200 && $status < 300,
        'http_status' => $status,
        'latency_ms' => round((microtime(true) - $started) * 1000, 2),
        'php_version' => $values['PHP_VERSION'] ?? null,
        'sapi' => $values['PHP_SAPI'] ?? null,
        'role' => $values['ROLE'] ?? null,
    ];
}

function render_page(string $target): never
{
    $safe_target = htmlspecialchars($target, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');

    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PHP2Shell ASLR Challenge</title>
  <style>
    :root{--bg:#071019;--panel:#0e1b28;--line:#263b4f;--text:#e7f1f8;--muted:#9fb3c3;--accent:#55d6be}
    body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,sans-serif}
    main{max-width:1000px;margin:auto;padding:48px 24px 96px}
    h1{font-size:clamp(2rem,5vw,3.4rem);line-height:1.1;margin:0}
    h2{border-bottom:1px solid var(--line);padding-bottom:.4rem;margin-top:3rem}
    .subtitle{color:var(--muted);max-width:75ch}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:28px}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}
    .label{color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.08em}
    .value{font-family:ui-monospace,monospace;margin-top:.3rem}
    code,pre{font-family:ui-monospace,monospace}
    pre{background:#0a141e;border:1px solid var(--line);border-radius:12px;padding:18px;overflow:auto}
    a{color:var(--accent)}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}
    th{color:var(--muted);font-size:.8rem;text-transform:uppercase}
    .warning{background:#201012;border:1px solid #8d3b37;color:#ffc7c3;border-radius:12px;padding:18px}
  </style>
</head>
<body>
<main>
  <p class="label">Authorized CTF laboratory</p>
  <h1>PHP2Shell ASLR Bypass</h1>
  <p class="subtitle">Exploit CVE-2026-109618 and CVE-2026-109619 in an isolated Apache mod_php worker. Recover two runtime addresses, derive the control-flow targets, and prove code execution while ASLR remains enabled.</p>
  <div class="grid">
    <div class="card"><div class="label">Challenge target</div><div class="value">$safe_target</div></div>
    <div class="card"><div class="label">Player requirements</div><div class="value">Python 3.11+, Git, HTTP</div></div>
    <div class="card"><div class="label">Docker required</div><div class="value">No</div></div>
    <div class="card"><div class="label">ASLR</div><div class="value">Enabled</div></div>
  </div>
  <h2>Player bundle</h2>
  <p><a href="/download/player-bundle.tar.gz">Download player-bundle.tar.gz</a></p>
  <h2>Commands</h2>
  <pre><code>tar -xzf player-bundle.tar.gz
./solve_remote.py $safe_target
./solve_remote.py $safe_target --shell</code></pre>
  <h2>ASLR derivation</h2>
  <table>
    <thead><tr><th>Stage</th><th>Runtime result</th><th>Purpose</th></tr></thead>
    <tbody>
      <tr><td>1</td><td>Zend heap chunk base</td><td>Locate the forged HashTable carrier</td></tr>
      <tr><td>2</td><td>libphp.so load base</td><td>Resolve symbols after randomization</td></tr>
      <tr><td>3</td><td>HTDATA and zif_system</td><td>Derive both final addresses from the leaks</td></tr>
    </tbody>
  </table>
  <h2>Live status</h2>
  <ul><li><a href="/api/challenge">Challenge metadata</a></li><li><a href="/api/status">Runtime status</a></li></ul>
  <h2>Safety</h2>
  <div class="warning">This deployment intentionally includes an unpatched PHP service. Expose it only through a private CTF network, VPN, or firewall.</div>
</main>
</body>
</html>
HTML;
    exit;
}

$path = request_path();
$target = environment('PUBLIC_TARGET_ORIGIN', DEFAULT_TARGET);

match ($path) {
    '/', '/index.html' => render_page($target),
    '/healthz' => respond_json(['status' => 'ok']),
    '/api/challenge' => respond_json([
        'name' => 'PHP2Shell ASLR Bypass',
        'cves' => ['CVE-2026-109618', 'CVE-2026-109619'],
        'public_target' => $target,
        'player_mode' => 'HTTP only; no Docker access required',
        'objective' => 'Recover /flag through the ASLR-aware chain',
        'aslr' => 'enabled and bypassed with runtime disclosures',
        'download' => '/download/player-bundle.tar.gz',
        'platform' => 'PHP ' . PHP_VERSION . ' / ' . PHP_SAPI,
    ]),
    '/api/status' => respond_json([
        'platform' => 'healthy',
        'vulnerable' => runtime_status(environment('INTERNAL_VULNERABLE_URL', 'http://vulnerable/version.php')),
        'patched' => runtime_status(environment('INTERNAL_PATCHED_URL', 'http://patched/version.php')),
    ]),
    default => respond_json(['error' => 'not found'], 404),
};
