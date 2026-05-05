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
function bv_sdv_resolve_path(string $storagePath): ?string {
    $storagePath = trim($storagePath);
    if ($storagePath === '' || str_contains($storagePath, "\0") || preg_match('#(^|/|\\\\)\.\.(/|\\\\|$)#', $storagePath)) {
        return null;
    }
    $normalized = str_replace('\\', '/', $storagePath);
    $normalized = ltrim($normalized, '/');
    if (str_starts_with($normalized, 'uploads/')) {
        $normalized = substr($normalized, 8);
    }

    $root = dirname(__DIR__, 2);
    $publicRoot = $root . '/public_html';
    $bases = [$publicRoot . '/uploads', $publicRoot, $root . '/uploads'];

    foreach ($bases as $base) {
        $baseReal = realpath($base);
        if ($baseReal === false) continue;
        $candidate = $baseReal . '/' . $normalized;
        $resolved = realpath($candidate);
        if ($resolved !== false && is_file($resolved) && str_starts_with($resolved, $baseReal . DIRECTORY_SEPARATOR)) {
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
if ($filePath === null) { http_response_code(404); exit('Document file not found or invalid path.'); }

$mime = strtolower((string)($doc['mime_type'] ?? 'application/octet-stream'));
$isImage = str_starts_with($mime, 'image/');
$isPdf = ($mime === 'application/pdf');

if (isset($_GET['download']) && $_GET['download'] === '1') {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . rawurlencode((string)($doc['original_name'] ?? ('document_' . $docId))) . '"');
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
