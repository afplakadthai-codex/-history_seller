<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$bvSdvRoot = dirname(__DIR__, 2);
$guardCandidates = [
    __DIR__ . '/_guard.php',
    __DIR__ . '/admin_auth.php',
    $bvSdvRoot . '/includes/admin_auth.php',
    $bvSdvRoot . '/includes/auth_admin.php',
];
foreach ($guardCandidates as $f) {
    if (is_file($f)) {
        require_once $f;
    }
}

function bv_sdv_h($value): string { return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8'); }
function bv_sdv_role(): string {
    $r = $_SESSION['role'] ?? ($_SESSION['admin_role'] ?? ($_SESSION['user']['role'] ?? ($_SESSION['admin']['role'] ?? '')));
    return strtolower(trim((string)$r));
}
function bv_sdv_admin_ok(): bool { return in_array(bv_sdv_role(), ['admin','super_admin','superadmin','owner'], true); }
function bv_sdv_db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $root = dirname(__DIR__, 2);
    foreach ([$root . '/config/db.php',$root . '/includes/db.php',$root . '/db.php'] as $f) { if (is_file($f)) require_once $f; }
    foreach (['pdo','db','conn','connection'] as $n) { if (isset($GLOBALS[$n]) && $GLOBALS[$n] instanceof PDO) return $pdo = $GLOBALS[$n]; }
    http_response_code(500); exit('PDO connection not available.');
}
function bv_sdv_safe_filename_ascii(string $filename, string $fallback): string {
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $base = pathinfo($filename, PATHINFO_FILENAME);
    $base = preg_replace('/[^A-Za-z0-9._-]+/', '_', $base);
    $base = trim((string)$base, '._-');
    if ($base === '') {
        $base = $fallback;
    }
    $safe = $base;
    if ($ext !== '') {
        $safe .= '.' . preg_replace('/[^A-Za-z0-9]+/', '', $ext);
    }
    return $safe;
}
function bv_sdv_guess_extension(string $mime, string $path): string {
    $ext = strtolower((string)pathinfo($path, PATHINFO_EXTENSION));
    if ($ext !== '') return $ext;
    $map = ['application/pdf' => 'pdf', 'image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif', 'image/webp' => 'webp'];
    return $map[strtolower($mime)] ?? '';
}
function bv_sdv_resolve_path(string $storagePath): ?string {
    $storagePath = trim($storagePath);
    if ($storagePath === '' || str_contains($storagePath, "\0") || str_contains($storagePath, '../') || str_contains($storagePath, '..\\') || preg_match('#(^|/|\\\\)\.\.(/|\\\\|$)#', $storagePath)) {
        return null;
    }

    $normalized = str_replace('\\', '/', $storagePath);
    $root = dirname(__DIR__, 2);
    $publicRoot = $root . '/public_html';
    $bases = [$root, $root . '/uploads', $publicRoot, $publicRoot . '/uploads'];

    $absoluteInput = preg_match('#^(?:[A-Za-z]:[\\/]|/)#', $normalized) === 1;
    if ($absoluteInput) {
        $resolvedAbs = realpath($normalized);
        if ($resolvedAbs === false || !is_file($resolvedAbs)) {
            return null;
        }
        foreach ($bases as $base) {
            $baseReal = realpath($base);
            if ($baseReal !== false && str_starts_with($resolvedAbs, rtrim($baseReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
                return $resolvedAbs;
            }
        }
        return null;
    }

    $normalized = ltrim($normalized, '/');
    if (str_starts_with($normalized, 'uploads/')) {
        $normalized = substr($normalized, 8);
    }

    foreach ($bases as $base) {
        $baseReal = realpath($base);
        if ($baseReal === false) continue;
        $candidate = $baseReal . '/' . $normalized;
        $resolved = realpath($candidate);
        if ($resolved !== false && is_file($resolved) && str_starts_with($resolved, rtrim($baseReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            return $resolved;
        }
    }
    return null;
}

if (!bv_sdv_admin_ok()) { http_response_code(403); exit('403 Forbidden'); }
header('X-Content-Type-Options: nosniff');

$docId = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($docId <= 0) { http_response_code(400); exit('Invalid document id.'); }

$pdo = bv_sdv_db();
$stmt = $pdo->prepare('SELECT * FROM seller_documents WHERE id = ? LIMIT 1');
$stmt->execute([$docId]);
$doc = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$doc) { http_response_code(404); exit('Document not found.'); }

$filePath = bv_sdv_resolve_path((string)($doc['storage_path'] ?? ''));
if ($filePath === null) { http_response_code(404); exit('Document file not found.'); }

$mime = strtolower((string)($doc['mime_type'] ?? 'application/octet-stream'));
$isImage = str_starts_with($mime, 'image/');
$isPdf = ($mime === 'application/pdf');

$originalName = trim((string)($doc['original_name'] ?? ''));
if ($originalName === '') {
    $ext = bv_sdv_guess_extension($mime, $filePath);
    $base = trim((string)($doc['document_type'] ?? 'seller-document'));
    if ($base === '') {
        $base = 'seller-document';
    }
    $fallback = $base . '-' . (int)$docId;
    $originalName = $fallback . ($ext !== '' ? ('.' . $ext) : '');
}
$asciiFallback = bv_sdv_safe_filename_ascii($originalName, 'seller-document-' . (int)$docId);

if (isset($_GET['download']) && $_GET['download'] === '1') {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . str_replace('"', '', $asciiFallback) . '"; filename*=UTF-8\'\'' . rawurlencode($originalName));
    header('Content-Length: ' . (string)filesize($filePath));
    readfile($filePath);
    exit;
}

if (isset($_GET['stream']) && $_GET['stream'] === '1') {
    if (!$isImage && !$isPdf) {
        http_response_code(403);
        exit;
    }
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . (string)filesize($filePath));
    readfile($filePath);
    exit;
}
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Document View</title>
<style>body{font-family:Arial,sans-serif;background:#f3f4f6;color:#111827}.container{max-width:1100px;margin:20px auto;padding:0 16px}.card{background:#fff;padding:16px;border:1px solid #e5e7eb;border-radius:8px}.kv{display:grid;grid-template-columns:220px 1fr;gap:8px;padding:6px 0;border-bottom:1px dashed #e5e7eb}.btn{display:inline-block;padding:8px 12px;border-radius:6px;background:#1f2937;color:#fff;text-decoration:none;margin-right:8px}</style>
</head><body><div class="container"><div class="card">
<h2>Seller Document</h2>
<div class="kv"><div>Document Label</div><div><?php echo bv_sdv_h($doc['document_label'] ?? '-'); ?></div></div>
<div class="kv"><div>Document Type</div><div><?php echo bv_sdv_h($doc['document_type'] ?? '-'); ?></div></div>
<div class="kv"><div>Original Name</div><div><?php echo bv_sdv_h($doc['original_name'] ?? '-'); ?></div></div>
<div class="kv"><div>MIME Type</div><div><?php echo bv_sdv_h($doc['mime_type'] ?? '-'); ?></div></div>
<div class="kv"><div>Uploaded At</div><div><?php echo bv_sdv_h((string)($doc['uploaded_at'] ?? '-')); ?></div></div>
<div style="margin:12px 0;">
<a class="btn" href="seller_application_history.php?id=<?php echo (int)($doc['application_id'] ?? 0); ?>">&larr; Back to Application</a>
<a class="btn" href="seller_document_view.php?id=<?php echo (int)$docId; ?>&download=1">Download</a>
</div>
<?php if ($isImage): ?>
<div><img alt="Document image" src="seller_document_view.php?id=<?php echo (int)$docId; ?>&stream=1" style="max-width:100%;height:auto;border:1px solid #ddd;"></div>
<?php elseif ($isPdf): ?>
<iframe src="seller_document_view.php?id=<?php echo (int)$docId; ?>&stream=1" style="width:100%;height:75vh;border:1px solid #ddd;"></iframe>
<?php else: ?>
<p>Preview is not available for this file type. Please use download.</p>
<?php endif; ?>
</div></div></body></html>
