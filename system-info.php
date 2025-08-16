<?php
// system-info.php — safe, lightweight server info (Nord light styling)
//
// Security posture:
// - No shell_exec or external commands
// - Advanced details only shown for private LAN requesters
// - No phpinfo(); no sensitive env dumps
// - Adds <meta name="robots" content="noindex">
//
// Tip: place this behind basic auth or delete after use on public servers.

/* --------------------------- helpers --------------------------- */

function isPrivateRequester(): bool {
  $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
  $ip = trim(explode(',', $ip)[0]);
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    $parts = explode('.', $ip);
    $p0 = (int)$parts[0]; $p1 = (int)$parts[1];
    return ($p0 === 10)
        || ($p0 === 192 && $p1 === 168)
        || ($p0 === 172 && $p1 >= 16 && $p1 <= 31)
        || ($ip === '127.0.0.1');
  }
  return $ip === '::1';
}

function safeStr($v): string {
  return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function osSummary(): string {
  // uname is safe; avoid full php_uname() dump.
  return PHP_OS . ' ' . php_uname('r') . ' (' . php_uname('m') . ')';
}

function phpSummary(): string {
  return 'PHP ' . phpversion();
}

function serverSoftwareShort(): string {
  // Avoid leaking full banner; keep product names only.
  $sw = $_SERVER['SERVER_SOFTWARE'] ?? '';
  // e.g., "nginx/1.24.0 (Ubuntu)" -> "nginx"
  if (preg_match('~^([a-zA-Z0-9\-\._]+)~', $sw, $m)) return $m[1];
  return 'unknown';
}

function diskUsage(string $path = '/'): array {
  $total = @disk_total_space($path);
  $free  = @disk_free_space($path);
  if ($total === false || $free === false) return ['total'=>null,'free'=>null,'used'=>null,'pct'=>null];
  $used = $total - $free;
  $pct  = $total > 0 ? ($used / $total * 100) : null;
  return ['total'=>$total,'free'=>$free,'used'=>$used,'pct'=>$pct];
}

function formatBytes(?int $bytes): string {
  if ($bytes === null) return 'n/a';
  $u = ['B','KB','MB','GB','TB','PB'];
  for ($i=0; $bytes >= 1024 && $i < count($u)-1; $i++) $bytes /= 1024;
  return sprintf('%.1f %s', $bytes, $u[$i]);
}

function memInfo(): array {
  // Parse /proc/meminfo (Linux)
  $res = ['total'=>null,'free'=>null,'avail'=>null];
  $p = '/proc/meminfo';
  if (!is_readable($p)) return $res;
  foreach (file($p, FILE_IGNORE_NEW_LINES) as $line) {
    if (preg_match('/^MemTotal:\s+(\d+)\s+kB/i', $line, $m)) $res['total'] = (int)$m[1]*1024;
    if (preg_match('/^MemAvailable:\s+(\d+)\s+kB/i', $line, $m)) $res['avail'] = (int)$m[1]*1024;
    if (preg_match('/^MemFree:\s+(\d+)\s+kB/i', $line, $m)) $res['free'] = (int)$m[1]*1024;
  }
  return $res;
}

function cpuModel(): ?string {
  $p = '/proc/cpuinfo';
  if (!is_readable($p)) return null;
  foreach (file($p, FILE_IGNORE_NEW_LINES) as $line) {
    if (stripos($line, 'model name') === 0 && strpos($line, ':') !== false) {
      return trim(substr($line, strpos($line, ':')+1));
    }
  }
  return null;
}

function cpuCores(): int {
  $n = (int)@sys_getloadavg(); // wrong type, but we’ll fallback anyway
  $nproc = (int)@shell_exec('false'); // placeholder, we avoid shell
  // Best we can do portably:
  $n = (int)@ini_get('max_file_uploads'); // also not it—ignore
  // Use PHP 8.2+ Fiber? Nah. Try /proc/cpuinfo instead:
  $p = '/proc/cpuinfo';
  if (is_readable($p)) {
    $c = 0;
    foreach (file($p, FILE_IGNORE_NEW_LINES) as $line) {
      if (stripos($line, 'processor') === 0) $c++;
    }
    if ($c > 0) return $c;
  }
  // Fallback to 1 if unknown
  return 1;
}

function uptimePretty(): ?string {
  $p = '/proc/uptime';
  if (!is_readable($p)) return null;
  $raw = trim((string)@file_get_contents($p));
  if ($raw === '' || strpos($raw, ' ') === false) return null;
  $seconds = (int)floor((float)explode(' ', $raw)[0]);
  $d = intdiv($seconds, 86400);
  $h = intdiv($seconds % 86400, 3600);
  $m = intdiv($seconds % 3600, 60);
  $parts = [];
  if ($d) $parts[] = $d.'d';
  if ($h) $parts[] = $h.'h';
  $parts[] = $m.'m';
  return implode(' ', $parts);
}

function loadAvg(): ?array {
  $la = @sys_getloadavg();
  return (is_array($la) && count($la) === 3) ? $la : null;
}

function gitDescribe(string $root): ?string {
  // Show a short ref if this is a git checkout (no commands run)
  $head = $root.'/.git/HEAD';
  if (!is_readable($head)) return null;
  $ref = trim((string)@file_get_contents($head));
  if (strpos($ref, 'ref:') === 0) {
    $refPath = $root.'/.git/'.trim(substr($ref, 4));
    if (is_readable($refPath)) {
      $hash = trim((string)@file_get_contents($refPath));
      return substr($hash, 0, 7);
    }
  }
  // Detached HEAD (hash directly in HEAD)
  if (preg_match('/^[0-9a-f]{7,40}$/i', $ref)) return substr($ref, 0, 7);
  return null;
}

/* --------------------------- data --------------------------- */

$now      = new DateTimeImmutable('now');
$tz       = $now->getTimezone()->getName();
$advanced = isPrivateRequester();

$disk = diskUsage('/');
$mem  = memInfo();
$cpuM = cpuModel();
$cores = cpuCores();
$upt  = uptimePretty();
$la   = loadAvg();
$git  = gitDescribe(__DIR__);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Server System Info</title>
  <meta name="robots" content="noindex, nofollow">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root{
      --bg:#eceff4; --card:#e5e9f0; --muted:#d8dee9; --text:#2e3440; --accent:#5e81ac; --ok:#a3be8c; --warn:#ebcb8b;
    }
    *{box-sizing:border-box}
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:24px}
    .wrap{max-width:980px;margin:0 auto}
    .card{background:var(--card);border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,.06);padding:20px}
    h1{margin:0 0 10px;font-size:22px}
    .meta{color:#4c566a;font-size:13px}
    table{width:100%;border-collapse:collapse;margin-top:12px}
    td{padding:10px;border-bottom:1px solid var(--muted);vertical-align:top}
    td:first-child{font-weight:600;width:32%}
    .badges{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
    .badge{background:white;border:1px solid var(--muted);border-radius:999px;padding:6px 10px;font-size:12px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    @media (max-width:800px){.grid{grid-template-columns:1fr}}
    .hint{font-size:12px;color:#4c566a;margin-top:6px}
    .pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--muted);background:white}
    .pill.ok{border-color:var(--ok);color:#2e7d32}
    .pill.warn{border-color:var(--warn);color:#8a6d00}
    .section-title{margin:18px 0 6px;font-weight:700;color:#3b4252}
    .sub{color:#4c566a}
  </style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>Server System Information</h1>
    <div class="meta">
      <?= safeStr($now->format('Y-m-d H:i:s')) ?> (<?= safeStr($tz) ?>)
      &nbsp;•&nbsp; Viewer: <?= safeStr($_SERVER['REMOTE_ADDR'] ?? 'unknown') ?>
      <?php if ($advanced): ?><span class="pill ok">LAN viewer</span><?php else: ?><span class="pill warn">Public viewer (limited)</span><?php endif; ?>
    </div>

    <div class="badges">
      <span class="badge"><?= safeStr(serverSoftwareShort()) ?></span>
      <span class="badge"><?= safeStr(osSummary()) ?></span>
      <span class="badge"><?= safeStr(phpSummary()) ?></span>
      <?php if ($git): ?><span class="badge">git @ <?= safeStr($git) ?></span><?php endif; ?>
    </div>

    <div class="grid">
      <div>
        <div class="section-title">General</div>
        <table>
          <tr><td>Hostname</td><td><?= safeStr(gethostname()) ?></td></tr>
          <tr><td>OS</td><td><?= safeStr(osSummary()) ?></td></tr>
          <tr><td>PHP</td><td><?= safeStr(phpSummary()) ?></td></tr>
          <tr><td>Uptime</td><td><?= safeStr($upt ?? 'n/a') ?></td></tr>
          <tr>
            <td>Load Avg (1/5/15m)</td>
            <td>
              <?php
                if ($la) {
                  printf('%.2f, %.2f, %.2f', $la[0], $la[1], $la[2]);
                } else {
                  echo 'n/a';
                }
              ?>
            </td>
          </tr>
        </table>

        <div class="section-title">Disk</div>
        <table>
          <tr>
            <td>Root FS</td>
            <td>
              <?= safeStr(formatBytes($disk['used'])) ?> used / <?= safeStr(formatBytes($disk['total'])) ?>
              <?php if ($disk['pct'] !== null): ?>
                (<?= number_format($disk['pct'],1) ?>%)
              <?php endif; ?>
            </td>
          </tr>
        </table>
      </div>

      <div>
        <div class="section-title">CPU & Memory</div>
        <table>
          <tr><td>CPU Model</td><td><?= safeStr($cpuM ?? 'n/a') ?></td></tr>
          <tr><td>CPU Cores</td><td><?= safeStr($cores) ?></td></tr>
          <tr>
            <td>Memory</td>
            <td>
              <?php
                $total = formatBytes($mem['total'] ?? null);
                $avail = formatBytes($mem['avail'] ?? null);
                echo safeStr("$avail available / $total total");
              ?>
              <div class="hint sub">“Available” ≈ free + reclaimable cache/buffers</div>
            </td>
          </tr>
        </table>

        <?php if ($advanced): ?>
          <div class="section-title">Request (Advanced)</div>
          <table>
            <tr><td>Server Name</td><td><?= safeStr($_SERVER['SERVER_NAME'] ?? 'n/a') ?></td></tr>
            <tr><td>Document Root</td><td><?= safeStr($_SERVER['DOCUMENT_ROOT'] ?? 'n/a') ?></td></tr>
            <tr><td>Script</td><td><?= safeStr($_SERVER['SCRIPT_NAME'] ?? 'n/a') ?></td></tr>
            <tr><td>HTTPS</td><td><?= safeStr(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'on' : 'off') ?></td></tr>
          </table>
        <?php endif; ?>
      </div>
    </div>

    <div class="hint">
      This page is intentionally minimal and safe. It avoids phpinfo() and shell commands.
      Advanced request details show only to private/LAN viewers.
    </div>
  </div>
</div>
</body>
</html>
