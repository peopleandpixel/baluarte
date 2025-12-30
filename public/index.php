<?php

require __DIR__ . '/../vendor/autoload.php';

use Baluarte\Database\DatabaseHandler;
use Baluarte\Service\CountryIpService;
use Symfony\Component\Yaml\Yaml;

$configPath = __DIR__ . '/../config/config.yaml';
$config = [];
if (file_exists($configPath)) {
    $config = Yaml::parseFile($configPath);
}

$dbPath = $config['database']['path'] ?? __DIR__ . '/../baluarte.sqlite';
// If it's a relative path, make it relative to the root
if (strpos($dbPath, '/') !== 0) {
    $dbPath = __DIR__ . '/../' . $dbPath;
}

$dbHandler = new DatabaseHandler($dbPath);
$countriesList = require __DIR__ . '/../src/countries.php';

// Handle POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if ($action === 'add_ban') {
        $type = $_POST['type'] ?? 'ip';
        $target = ($type === 'country') ? ($_POST['target_country'] ?? '') : ($_POST['target'] ?? '');
        $duration = (int)($_POST['duration'] ?? 1440);
        if ($target) {
            $dbHandler->addBan($target, $duration, $type);
        }
    } elseif ($action === 'remove_ban') {
        $ip = $_POST['ip'] ?? '';
        if ($ip) {
            $dbHandler->removeBan($ip);
        }
    }
    header('Location: /');
    exit;
}

$uri = $_SERVER['REQUEST_URI'];

if ($uri === '/blocked-ips') {
    $ips = $dbHandler->getActiveBansByType('ip');
    $ranges = $dbHandler->getActiveBansByType('range');
    $countries = $dbHandler->getActiveBansByType('country');

    $allBlocked = array_merge($ips, $ranges);

    if (!empty($countries)) {
        $countryIpService = new CountryIpService(__DIR__ . '/../data/cache/countries');
        foreach ($countries as $countryCode) {
            $countryRanges = $countryIpService->getIpRanges($countryCode);
            $allBlocked = array_merge($allBlocked, $countryRanges);
        }
    }

    header('Content-Type: text/plain');
    echo implode("\n", array_unique($allBlocked));
    exit;
}

$detectedIps = $dbHandler->getAllDetectedIps();
$activeBansDetailed = $dbHandler->getActiveBansDetailed();

?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Baluarte Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet" type="text/css" />
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="bg-base-200 min-h-screen">
<div class="navbar bg-base-100 shadow-lg mb-8">
    <div class="flex-1 px-2 mx-2">
        <span class="text-lg font-bold">🛡️ Baluarte</span>
    </div>
    <div class="flex-none">
        <ul class="menu menu-horizontal px-1">
            <li><a href="/" class="active">Dashboard</a></li>
            <li><a href="/blocked-ips">Blocked IPs (CSV)</a></li>
        </ul>
    </div>
</div>

<div class="container mx-auto p-4 max-w-6xl">
    
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <!-- Stats -->
        <div class="stats shadow bg-base-100 lg:col-span-3">
            <div class="stat">
                <div class="stat-figure text-primary">
                    <i class="fa-solid fa-user-slash fa-2x"></i>
                </div>
                <div class="stat-title">Active Bans</div>
                <div class="stat-value text-primary"><?php echo count($activeBansDetailed); ?></div>
                <div class="stat-desc">Total IPs, ranges, and countries</div>
            </div>
            
            <div class="stat">
                <div class="stat-figure text-secondary">
                    <i class="fa-solid fa-eye fa-2x"></i>
                </div>
                <div class="stat-title">Recent Detections</div>
                <div class="stat-value text-secondary"><?php echo count($detectedIps); ?></div>
                <div class="stat-desc">In the malicious logs database</div>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <!-- Add Ban Form -->
        <div class="card bg-base-100 shadow-xl">
            <div class="card-body">
                <h2 class="card-title mb-4">Manual Ban</h2>
                <form method="POST">
                    <input type="hidden" name="action" value="add_ban">
                    <div class="form-control w-full">
                        <label class="label">
                            <span class="label-text">Ban Type</span>
                        </label>
                        <select name="type" class="select select-bordered w-full" id="ban_type" onchange="toggleBanInput()">
                            <option value="ip">Single IP</option>
                            <option value="range">IP Range (CIDR)</option>
                            <option value="country">Country</option>
                        </select>
                    </div>

                    <div class="form-control w-full mt-4" id="target_input_container">
                        <label class="label">
                            <span class="label-text" id="target_label">IP Address</span>
                        </label>
                        <input type="text" name="target" id="target_input" placeholder="e.g. 1.2.3.4" class="input input-bordered w-full" />
                    </div>

                    <div class="form-control w-full mt-4 hidden" id="country_input_container">
                        <label class="label">
                            <span class="label-text">Select Country</span>
                        </label>
                        <select name="target_country" id="country_select" class="select select-bordered w-full">
                            <option value="">-- Choose Country --</option>
                            <?php foreach ($countriesList as $c): ?>
                                <option value="<?php echo htmlspecialchars($c['code']); ?>">
                                    <?php echo $c['flag']; ?> <?php echo htmlspecialchars($c['name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="form-control w-full mt-4">
                        <label class="label">
                            <span class="label-text">Duration (minutes)</span>
                        </label>
                        <input type="number" name="duration" value="1440" class="input input-bordered w-full" />
                        <label class="label">
                            <span class="label-text-alt">1440 = 24 hours</span>
                        </label>
                    </div>

                    <div class="card-actions justify-end mt-6">
                        <button type="submit" class="btn btn-primary w-full">Add Ban</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Active Bans Table -->
        <div class="card bg-base-100 shadow-xl lg:col-span-2">
            <div class="card-body">
                <h2 class="card-title mb-4">Currently Blocked</h2>
                <div class="overflow-x-auto">
                    <table class="table w-full">
                        <thead>
                        <tr>
                            <th>Target</th>
                            <th>Type</th>
                            <th>Banned At</th>
                            <th>Expires At</th>
                            <th>Action</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($activeBansDetailed as $ban): ?>
                            <tr>
                                <td>
                                    <?php if ($ban['type'] === 'country'): ?>
                                        <?php 
                                            $countryCode = $ban['ip_address'];
                                            $found = array_filter($countriesList, fn($c) => $c['code'] === $countryCode);
                                            $country = reset($found);
                                            echo ($country['flag'] ?? '') . ' ' . htmlspecialchars($country['name'] ?? $countryCode);
                                        ?>
                                    <?php else: ?>
                                        <code class="text-sm"><?php echo htmlspecialchars($ban['ip_address']); ?></code>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <div class="badge <?php 
                                        echo match($ban['type']) {
                                            'ip' => 'badge-ghost',
                                            'range' => 'badge-warning',
                                            'country' => 'badge-error',
                                            default => 'badge-ghost'
                                        };
                                    ?>">
                                        <?php echo htmlspecialchars($ban['type']); ?>
                                    </div>
                                </td>
                                <td class="text-xs"><?php echo htmlspecialchars($ban['banned_at']); ?></td>
                                <td class="text-xs"><?php echo htmlspecialchars($ban['expires_at']); ?></td>
                                <td>
                                    <form method="POST" onsubmit="return confirm('Really remove this ban?')">
                                        <input type="hidden" name="action" value="remove_ban">
                                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ban['ip_address']); ?>">
                                        <button type="submit" class="btn btn-ghost btn-xs text-error">
                                            <i class="fa-solid fa-trash"></i>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($activeBansDetailed)): ?>
                            <tr><td colspan="5" class="text-center italic opacity-50">No active bans found.</td></tr>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Recent Detections -->
        <div class="card bg-base-100 shadow-xl lg:col-span-3">
            <div class="card-body">
                <h2 class="card-title mb-4">Recent Detections</h2>
                <div class="overflow-x-auto">
                    <table class="table table-zebra w-full">
                        <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Source</th>
                            <th>Location</th>
                            <th>Detected At</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($detectedIps as $ip): ?>
                            <tr>
                                <td>
                                    <div class="flex items-center space-x-2">
                                        <code class="text-sm"><?php echo htmlspecialchars($ip['ip_address']); ?></code>
                                        <form method="POST" class="inline">
                                            <input type="hidden" name="action" value="add_ban">
                                            <input type="hidden" name="type" value="ip">
                                            <input type="hidden" name="target" value="<?php echo htmlspecialchars($ip['ip_address']); ?>">
                                            <button type="submit" class="btn btn-ghost btn-xs p-0 min-h-0 h-auto" title="Ban now">
                                                <i class="fa-solid fa-ban text-error"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                                <td class="max-w-xs truncate" title="<?php echo htmlspecialchars($ip['reason']); ?>">
                                    <?php echo htmlspecialchars($ip['reason']); ?>
                                </td>
                                <td><span class="badge badge-info badge-sm"><?php echo htmlspecialchars($ip['log_source']); ?></span></td>
                                <td class="text-sm">
                                    <?php echo htmlspecialchars(($ip['city'] ?? '') . ($ip['city'] && $ip['country'] ? ', ' : '') . ($ip['country'] ?? '') ?: 'Unknown'); ?>
                                    <?php if ($ip['isp']): ?>
                                        <br><small class="opacity-60"><?php echo htmlspecialchars($ip['isp']); ?></small>
                                    <?php endif; ?>
                                </td>
                                <td class="text-xs"><?php echo htmlspecialchars($ip['detected_at']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($detectedIps)): ?>
                            <tr><td colspan="5" class="text-center italic opacity-50">No detections found.</td></tr>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    function toggleBanInput() {
        const type = document.getElementById('ban_type').value;
        const targetInputContainer = document.getElementById('target_input_container');
        const countryInputContainer = document.getElementById('country_input_container');
        const targetLabel = document.getElementById('target_label');
        const targetInput = document.getElementById('target_input');

        if (type === 'country') {
            targetInputContainer.classList.add('hidden');
            countryInputContainer.classList.remove('hidden');
        } else {
            targetInputContainer.classList.remove('hidden');
            countryInputContainer.classList.add('hidden');
            
            if (type === 'range') {
                targetLabel.innerText = 'IP Range (CIDR)';
                targetInput.placeholder = 'e.g. 192.168.1.0/24';
            } else {
                targetLabel.innerText = 'IP Address';
                targetInput.placeholder = 'e.g. 1.2.3.4';
            }
        }
    }
</script>
</body>
</html>
