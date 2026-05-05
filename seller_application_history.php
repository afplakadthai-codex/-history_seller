<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$bvSahRoot = dirname(__DIR__, 2);
$bvSahGuardCandidates = [
    __DIR__ . '/_guard.php',
    __DIR__ . '/admin_auth.php',
    $bvSahRoot . '/includes/admin_auth.php',
    $bvSahRoot . '/includes/auth_admin.php',
];
foreach ($bvSahGuardCandidates as $guardFile) {
    if (is_file($guardFile)) {
        require_once $guardFile;
    }
}

function bv_sah_h($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function bv_sah_db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $root = dirname(__DIR__, 2);
    $candidates = [
        $root . '/config/db.php',
        $root . '/includes/db.php',
        $root . '/db.php',
    ];

    foreach ($candidates as $file) {
        if (is_file($file)) {
            require_once $file;
        }
    }

    $vars = ['pdo', 'db', 'conn', 'connection', 'mysqli', 'database'];
    foreach ($vars as $name) {
        if (isset($GLOBALS[$name]) && $GLOBALS[$name] instanceof PDO) {
            $pdo = $GLOBALS[$name];
            return $pdo;
        }
    }

    foreach (get_defined_vars() as $v) {
        if ($v instanceof PDO) {
            $pdo = $v;
            return $pdo;
        }
    }

    http_response_code(500);
    exit('PDO connection not available.');
}

function bv_sah_current_role(): string
{
    $candidates = [
        $_SESSION['role'] ?? null,
        $_SESSION['admin_role'] ?? null,
        $_SESSION['user']['role'] ?? null,
        $_SESSION['admin']['role'] ?? null,
        $_SESSION['auth']['role'] ?? null,
        $GLOBALS['current_user']['role'] ?? null,
    ];

    foreach ($candidates as $role) {
        if (is_string($role) && $role !== '') {
            return strtolower(trim($role));
        }
    }

    return '';
}

function bv_sah_is_super_admin(): bool
{
    $allowed = ['admin', 'super_admin', 'superadmin', 'owner'];
    return in_array(bv_sah_current_role(), $allowed, true);
}

function bv_sah_table_exists(PDO $pdo, string $table): bool
{
    static $cache = [];
    if (isset($cache[$table])) {
        return $cache[$table];
    }
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?');
    $stmt->execute([$table]);
    $cache[$table] = ((int)$stmt->fetchColumn() > 0);
    return $cache[$table];
}

function bv_sah_columns(PDO $pdo, string $table): array
{
    static $cache = [];
    $key = $table;
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    if (!bv_sah_table_exists($pdo, $table)) {
        $cache[$key] = [];
        return [];
    }
    $stmt = $pdo->prepare('SELECT COLUMN_NAME FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?');
    $stmt->execute([$table]);
    $cache[$key] = array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    return $cache[$key];
}

function bv_sah_has_col(PDO $pdo, string $table, string $column): bool
{
    return in_array($column, bv_sah_columns($pdo, $table), true);
}

function bv_sah_build_url(array $params = []): string
{
    $base = strtok($_SERVER['REQUEST_URI'] ?? 'seller_application_history.php', '?') ?: 'seller_application_history.php';
    $query = array_merge($_GET, $params);
    foreach ($query as $k => $v) {
        if ($v === null || $v === '') {
            unset($query[$k]);
        }
    }
    return $base . (empty($query) ? '' : ('?' . http_build_query($query)));
}

function bv_sah_status_badge(?string $status): string
{
    $s = strtolower((string)$status);
    $map = [
        'submitted' => '#3b82f6',
        'under_review' => '#f59e0b',
        'approved' => '#10b981',
        'rejected' => '#ef4444',
        'suspended' => '#6b7280',
    ];
    $color = $map[$s] ?? '#4b5563';
    $label = $s === '' ? 'unknown' : $s;
    return '<span style="display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;background:' . bv_sah_h($color) . ';font-size:12px;">' . bv_sah_h($label) . '</span>';
}

function bv_sah_format_date($value): string
{
    if (!$value) {
        return '-';
    }
    $ts = strtotime((string)$value);
    if ($ts === false) {
        return bv_sah_h((string)$value);
    }
    return date('Y-m-d H:i:s', $ts);
}

function bv_sah_file_size($bytes): string
{
    $size = (float)$bytes;
    if ($size <= 0) {
        return '-';
    }
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }
    return number_format($size, $i === 0 ? 0 : 2) . ' ' . $units[$i];
}

function bv_sah_mask_tail(?string $value, int $visible = 4): string
{
    $val = preg_replace('/\s+/', '', (string)$value);
    if ($val === '') {
        return '-';
    }
    $len = strlen($val);
    if ($len <= $visible) {
        return str_repeat('*', $len);
    }
    return str_repeat('*', $len - $visible) . substr($val, -$visible);
}

if (!bv_sah_is_super_admin()) {
    http_response_code(403);
    exit('403 Forbidden');
}

$pdo = bv_sah_db();
if (!bv_sah_table_exists($pdo, 'seller_applications')) {
    http_response_code(500);
    exit('seller_applications table not found.');
}

$summary = [
    'total' => 0,
    'submitted' => 0,
    'under_review' => 0,
    'approved' => 0,
    'rejected' => 0,
    'suspended' => 0,
];
$stmtSummary = $pdo->query('SELECT application_status, COUNT(*) AS cnt FROM seller_applications GROUP BY application_status');
$rowsSummary = $stmtSummary ? $stmtSummary->fetchAll(PDO::FETCH_ASSOC) : [];
foreach ($rowsSummary as $r) {
    $status = strtolower((string)($r['application_status'] ?? ''));
    $cnt = (int)($r['cnt'] ?? 0);
    $summary['total'] += $cnt;
    if (isset($summary[$status])) {
        $summary[$status] += $cnt;
    }
}

$detailId = isset($_GET['id']) ? (int)$_GET['id'] : 0;

?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Seller Application History</title>
<style>
body{font-family:Arial,sans-serif;background:#f3f4f6;color:#111827;margin:0}
.container{max-width:1280px;margin:20px auto;padding:0 16px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.sum{padding:12px;border-radius:8px;background:#f9fafb;border:1px solid #e5e7eb}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #e5e7eb;padding:10px;text-align:left;font-size:14px;vertical-align:top}
input,select{padding:8px;border:1px solid #d1d5db;border-radius:6px}
.btn{display:inline-block;padding:8px 12px;border-radius:6px;background:#1f2937;color:#fff;text-decoration:none;border:none;cursor:pointer}
.btn.light{background:#6b7280}.kv{display:grid;grid-template-columns:260px 1fr;gap:8px;padding:6px 0;border-bottom:1px dashed #e5e7eb}
</style>
</head>
<body>
<div class="container">
<h1>Seller Application History</h1>
<div class="card"><div class="grid">
<?php foreach ($summary as $k => $v): ?><div class="sum"><strong><?php echo bv_sah_h(ucwords(str_replace('_', ' ', $k))); ?></strong><br><?php echo (int)$v; ?></div><?php endforeach; ?>
</div></div>
<?php if ($detailId > 0):
    $appStmt = $pdo->prepare('SELECT sa.*, u.* FROM seller_applications sa LEFT JOIN users u ON u.id = sa.user_id WHERE sa.id = ? LIMIT 1');
    $appStmt->execute([$detailId]);
    $app = $appStmt->fetch(PDO::FETCH_ASSOC);
    if (!$app): ?>
        <div class="card">Application not found. <a class="btn light" href="<?php echo bv_sah_h(bv_sah_build_url(['id' => null])); ?>">Back</a></div>
    <?php else:
        $docStmt = $pdo->prepare('SELECT * FROM seller_documents WHERE application_id = ? ORDER BY uploaded_at DESC, id DESC');
        $docStmt->execute([$detailId]);
        $docs = $docStmt->fetchAll(PDO::FETCH_ASSOC);

        $history = [];
        if (bv_sah_table_exists($pdo, 'seller_application_status_history')) {
            $hCols = bv_sah_columns($pdo, 'seller_application_status_history');
            $timeCol = in_array('created_at', $hCols, true) ? 'created_at' : (in_array('changed_at', $hCols, true) ? 'changed_at' : 'id');
            $hs = $pdo->prepare('SELECT * FROM seller_application_status_history WHERE application_id = ? ORDER BY ' . $timeCol . ' DESC, id DESC');
            $hs->execute([$detailId]);
            $history = $hs->fetchAll(PDO::FETCH_ASSOC);
        }
        ?>
        <div class="card"><a class="btn light" href="<?php echo bv_sah_h(bv_sah_build_url(['id' => null])); ?>">&larr; Back</a></div>
        <div class="card"><h3>A. Applicant Profile</h3>
            <div class="kv"><div>User ID</div><div><?php echo (int)($app['user_id'] ?? 0); ?></div></div>
            <div class="kv"><div>First Name</div><div><?php echo bv_sah_h($app['first_name'] ?? '-'); ?></div></div>
            <div class="kv"><div>Last Name</div><div><?php echo bv_sah_h($app['last_name'] ?? '-'); ?></div></div>
            <div class="kv"><div>Email</div><div><?php echo bv_sah_h($app['email'] ?? '-'); ?></div></div>
            <div class="kv"><div>Phone</div><div><?php echo bv_sah_h($app['phone'] ?? '-'); ?></div></div>
            <div class="kv"><div>Role</div><div><?php echo bv_sah_h($app['role'] ?? '-'); ?></div></div>
        </div>
        <div class="card"><h3>B. Seller Application</h3>
            <div class="kv"><div>Application ID</div><div><?php echo (int)$app['id']; ?></div></div>
            <div class="kv"><div>Status</div><div><?php echo bv_sah_status_badge($app['application_status'] ?? ''); ?></div></div>
            <div class="kv"><div>Farm Name</div><div><?php echo bv_sah_h($app['farm_name'] ?? '-'); ?></div></div>
            <div class="kv"><div>Farm Phone</div><div><?php echo bv_sah_h($app['farm_phone'] ?? '-'); ?></div></div>
            <div class="kv"><div>Submitted At</div><div><?php echo bv_sah_h(bv_sah_format_date($app['submitted_at'] ?? null)); ?></div></div>
            <div class="kv"><div>Reviewed At</div><div><?php echo bv_sah_h(bv_sah_format_date($app['reviewed_at'] ?? null)); ?></div></div>
            <div class="kv"><div>Reviewed By</div><div><?php echo bv_sah_h($app['reviewed_by'] ?? '-'); ?></div></div>
            <div class="kv"><div>Admin Review Note</div><div><?php echo nl2br(bv_sah_h($app['admin_review_note'] ?? '-')); ?></div></div>
        </div>
        <div class="card"><h3>C. Farm Address</h3>
            <?php foreach (['farm_address_line1','farm_address_line2','farm_road','farm_subdistrict','farm_district','farm_province','farm_postal_code'] as $f): ?>
                <div class="kv"><div><?php echo bv_sah_h($f); ?></div><div><?php echo bv_sah_h($app[$f] ?? '-'); ?></div></div>
            <?php endforeach; ?>
        </div>
        <div class="card"><h3>D. Certificate</h3>
            <div class="kv"><div>Certificate Name</div><div><?php echo bv_sah_h($app['certificate_name'] ?? '-'); ?></div></div>
            <div class="kv"><div>Certificate Number</div><div><?php echo bv_sah_h($app['certificate_number'] ?? '-'); ?></div></div>
        </div>
        <div class="card"><h3>E. Identity</h3>
            <div class="kv"><div>ID Card Number</div><div><?php echo bv_sah_h(bv_sah_mask_tail($app['id_card_number'] ?? '')); ?></div></div>
        </div>
        <div class="card"><h3>F. Bank Info</h3>
            <div class="kv"><div>Bank Name</div><div><?php echo bv_sah_h($app['bank_name'] ?? '-'); ?></div></div>
            <div class="kv"><div>Bank Branch Name</div><div><?php echo bv_sah_h($app['bank_branch_name'] ?? '-'); ?></div></div>
            <div class="kv"><div>Bank Account Name</div><div><?php echo bv_sah_h($app['bank_account_name'] ?? '-'); ?></div></div>
            <div class="kv"><div>Bank Account Number</div><div><?php echo bv_sah_h(bv_sah_mask_tail($app['bank_account_number'] ?? '')); ?></div></div>
        </div>
        <div class="card"><h3>G. Terms / Privacy</h3>
            <?php foreach (['accepted_terms_version','accepted_terms_at','accepted_terms_ip','accepted_privacy_version','accepted_privacy_at','accepted_privacy_ip'] as $f): ?>
                <div class="kv"><div><?php echo bv_sah_h($f); ?></div><div><?php echo bv_sah_h(($f === 'accepted_terms_at' || $f === 'accepted_privacy_at') ? bv_sah_format_date($app[$f] ?? null) : ($app[$f] ?? '-')); ?></div></div>
            <?php endforeach; ?>
        </div>
        <div class="card"><h3>H. Map / Location</h3>
            <div class="kv"><div>Place Name</div><div><?php echo bv_sah_h($app['map_place_name'] ?? '-'); ?></div></div>
            <div class="kv"><div>Latitude</div><div><?php echo bv_sah_h($app['map_lat'] ?? '-'); ?></div></div>
            <div class="kv"><div>Longitude</div><div><?php echo bv_sah_h($app['map_lng'] ?? '-'); ?></div></div>
            <?php if (($app['map_lat'] ?? '') !== '' && ($app['map_lng'] ?? '') !== ''): ?>
            <div class="kv"><div>Map Link</div><div><a target="_blank" rel="noopener" href="https://maps.google.com/?q=<?php echo rawurlencode((string)$app['map_lat'] . ',' . (string)$app['map_lng']); ?>">Open Google Maps</a></div></div>
            <?php endif; ?>
        </div>
        <div class="card"><h3>I. Attached Documents</h3>
            <table><thead><tr><th>Label</th><th>Type</th><th>Original Name</th><th>MIME</th><th>Size</th><th>Uploaded</th><th>Action</th></tr></thead><tbody>
            <?php if (!$docs): ?><tr><td colspan="7">No documents.</td></tr><?php else: foreach ($docs as $d): ?>
                <tr>
                    <td><?php echo bv_sah_h($d['document_label'] ?? '-'); ?></td>
                    <td><?php echo bv_sah_h($d['document_type'] ?? '-'); ?></td>
                    <td><?php echo bv_sah_h($d['original_name'] ?? '-'); ?></td>
                    <td><?php echo bv_sah_h($d['mime_type'] ?? '-'); ?></td>
                    <td><?php echo bv_sah_h(bv_sah_file_size($d['file_size_bytes'] ?? 0)); ?></td>
                    <td><?php echo bv_sah_h(bv_sah_format_date($d['uploaded_at'] ?? null)); ?></td>
                    <td><a class="btn" href="seller_document_view.php?id=<?php echo (int)$d['id']; ?>">View</a></td>
                </tr>
            <?php endforeach; endif; ?>
            </tbody></table>
        </div>
        <div class="card"><h3>J. Status History</h3>
            <table><thead><tr><th>Old</th><th>New</th><th>Changed By</th><th>Note/Reason</th><th>Changed At</th></tr></thead><tbody>
            <?php if (!$history): ?><tr><td colspan="5">No status history.</td></tr><?php else: foreach ($history as $h):
                $note = $h['note'] ?? ($h['reason'] ?? ($h['change_note'] ?? '-'));
                $changedAt = $h['created_at'] ?? ($h['changed_at'] ?? ($h['updated_at'] ?? null));
                ?>
                <tr>
                    <td><?php echo bv_sah_h($h['old_status'] ?? '-'); ?></td>
                    <td><?php echo bv_sah_h($h['new_status'] ?? '-'); ?></td>
                    <td><?php echo bv_sah_h((string)($h['changed_by'] ?? ($h['updated_by'] ?? '-'))); ?></td>
                    <td><?php echo bv_sah_h($note); ?></td>
                    <td><?php echo bv_sah_h(bv_sah_format_date($changedAt)); ?></td>
                </tr>
            <?php endforeach; endif; ?>
            </tbody></table>
        </div>
    <?php endif; ?>
<?php else:
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = 25;
    $offset = ($page - 1) * $perPage;
    $status = trim((string)($_GET['status'] ?? ''));
    $keyword = trim((string)($_GET['keyword'] ?? ''));
    $dateFrom = trim((string)($_GET['date_from'] ?? ''));
    $dateTo = trim((string)($_GET['date_to'] ?? ''));

    $where = [];
    $bind = [];
    if ($status !== '') { $where[] = 'sa.application_status = ?'; $bind[] = $status; }
    if ($dateFrom !== '') { $where[] = 'DATE(sa.submitted_at) >= ?'; $bind[] = $dateFrom; }
    if ($dateTo !== '') { $where[] = 'DATE(sa.submitted_at) <= ?'; $bind[] = $dateTo; }
    if ($keyword !== '') {
        $where[] = '(sa.farm_name LIKE ? OR u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR sa.farm_phone LIKE ? OR sa.certificate_number LIKE ?)';
        for ($i = 0; $i < 6; $i++) { $bind[] = '%' . $keyword . '%'; }
    }
    $whereSql = $where ? (' WHERE ' . implode(' AND ', $where)) : '';

    $countSql = 'SELECT COUNT(*) FROM seller_applications sa LEFT JOIN users u ON u.id = sa.user_id' . $whereSql;
    $cs = $pdo->prepare($countSql); $cs->execute($bind); $totalRows = (int)$cs->fetchColumn();
    $totalPages = max(1, (int)ceil($totalRows / $perPage));
    if ($page > $totalPages) { $page = $totalPages; $offset = ($page - 1) * $perPage; }

    $sql = 'SELECT sa.id, sa.user_id, sa.farm_name, sa.farm_phone, sa.application_status, sa.submitted_at, sa.reviewed_at,
                   u.first_name, u.last_name, u.email,
                   (SELECT COUNT(*) FROM seller_documents sd WHERE sd.application_id = sa.id) AS documents_count
            FROM seller_applications sa
            LEFT JOIN users u ON u.id = sa.user_id' . $whereSql . '
            ORDER BY sa.id DESC LIMIT ' . (int)$perPage . ' OFFSET ' . (int)$offset;
    $st = $pdo->prepare($sql); $st->execute($bind); $apps = $st->fetchAll(PDO::FETCH_ASSOC);
?>
<div class="card">
<form method="get" style="display:flex;flex-wrap:wrap;gap:8px;align-items:end;">
<div><label>Status<br><select name="status"><option value="">All</option><?php foreach (['submitted','under_review','approved','rejected','suspended'] as $s): ?><option value="<?php echo bv_sah_h($s); ?>"<?php echo $status===$s?' selected':''; ?>><?php echo bv_sah_h($s); ?></option><?php endforeach; ?></select></label></div>
<div><label>Keyword<br><input type="text" name="keyword" value="<?php echo bv_sah_h($keyword); ?>"></label></div>
<div><label>Date From<br><input type="date" name="date_from" value="<?php echo bv_sah_h($dateFrom); ?>"></label></div>
<div><label>Date To<br><input type="date" name="date_to" value="<?php echo bv_sah_h($dateTo); ?>"></label></div>
<div><button class="btn" type="submit">Filter</button></div>
</form>
</div>
<div class="card"><table><thead><tr><th>Application ID</th><th>Farm Name</th><th>Applicant Name</th><th>Email</th><th>Phone</th><th>Status</th><th>Submitted At</th><th>Reviewed At</th><th>Documents Count</th><th>Action</th></tr></thead><tbody>
<?php if (!$apps): ?><tr><td colspan="10">No applications found.</td></tr><?php else: foreach ($apps as $a): ?>
<tr>
<td><?php echo (int)$a['id']; ?></td>
<td><?php echo bv_sah_h($a['farm_name'] ?? '-'); ?></td>
<td><?php echo bv_sah_h(trim((string)($a['first_name'] ?? '') . ' ' . (string)($a['last_name'] ?? '')) ?: '-'); ?></td>
<td><?php echo bv_sah_h($a['email'] ?? '-'); ?></td>
<td><?php echo bv_sah_h($a['farm_phone'] ?? '-'); ?></td>
<td><?php echo bv_sah_status_badge($a['application_status'] ?? ''); ?></td>
<td><?php echo bv_sah_h(bv_sah_format_date($a['submitted_at'] ?? null)); ?></td>
<td><?php echo bv_sah_h(bv_sah_format_date($a['reviewed_at'] ?? null)); ?></td>
<td><?php echo (int)($a['documents_count'] ?? 0); ?></td>
<td><a class="btn" href="<?php echo bv_sah_h(bv_sah_build_url(['id' => (int)$a['id'], 'page' => null])); ?>">View</a></td>
</tr>
<?php endforeach; endif; ?>
</tbody></table>
<div style="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap;">
<?php for ($p=max(1,$page-2);$p<=min($totalPages,$page+2);$p++): ?>
<a class="btn<?php echo $p===$page?'':' light'; ?>" href="<?php echo bv_sah_h(bv_sah_build_url(['page'=>$p])); ?>"><?php echo $p; ?></a>
<?php endfor; ?>
</div>
</div>
<?php endif; ?>
</div>
</body></html>
