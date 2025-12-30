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
if (!str_starts_with($dbPath, '/')) {
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
    } elseif ($action === 'update_config') {
        $newConfig = $config;
        
        // General settings
        $newConfig['database']['path'] = $_POST['db_path'] ?? 'baluarte.sqlite';
        $newConfig['api']['abuseipdb']['key'] = $_POST['abuseipdb_key'] ?? '';
        $newConfig['geoip']['database_path'] = $_POST['geoip_path'] ?? '';
        $newConfig['firewall']['enabled'] = isset($_POST['firewall_enabled']);
        $newConfig['firewall']['driver'] = $_POST['firewall_driver'] ?? 'ufw';
        $newConfig['notifications']['webhook']['url'] = $_POST['webhook_url'] ?? '';
        
        // Patterns
        $newConfig['patterns'] = [];
        if (isset($_POST['patterns']) && is_array($_POST['patterns'])) {
            foreach ($_POST['patterns'] as $id => $pattern) {
                if (!empty($pattern['regex'])) {
                    $newConfig['patterns'][$id] = [
                        'regex' => $pattern['regex'],
                        'reason' => $pattern['reason'] ?? '',
                        'enabled' => isset($pattern['enabled'])
                    ];
                    if (!empty($pattern['format'])) {
                        $newConfig['patterns'][$id]['format'] = $pattern['format'];
                    }
                    if (!empty($pattern['field'])) {
                        $newConfig['patterns'][$id]['field'] = $pattern['field'];
                    }
                }
            }
        }
        
        // Add new pattern
        $newId = $_POST['new_pattern_id'] ?? '';
        $newRegex = $_POST['new_pattern_regex'] ?? '';
        if (!empty($newId) && !empty($newRegex)) {
            $newConfig['patterns'][$newId] = [
                'regex' => $newRegex,
                'reason' => $_POST['new_pattern_reason'] ?? '',
                'enabled' => true
            ];
            if (!empty($_POST['new_pattern_format'])) {
                $newConfig['patterns'][$newId]['format'] = $_POST['new_pattern_format'];
            }
            if (!empty($_POST['new_pattern_field'])) {
                $newConfig['patterns'][$newId]['field'] = $_POST['new_pattern_field'];
            }
        }

        file_put_contents($configPath, Yaml::dump($newConfig, 4));
        header('Location: /?page=settings&saved=1');
        exit;
    }
    header('Location: /');
    exit;
}

$page = $_GET['page'] ?? 'dashboard';

$uri = $_SERVER['REQUEST_URI'];

if ($uri === '/blocked-ips') {
    try {
        $ips = $dbHandler->getActiveBansByType('ip');
    } catch (\Doctrine\DBAL\Exception $e) {
        $ips = [];
    }
    try {
        $ranges = $dbHandler->getActiveBansByType('range');
    } catch (\Doctrine\DBAL\Exception $e) {
        $ranges = [];
    }
    try {
        $countries = $dbHandler->getActiveBansByType('country');
    } catch (\Doctrine\DBAL\Exception $e) {
        $countries = [];
    }

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

try {
    $detectedIps = $dbHandler->getAllDetectedIps();
} catch (\Doctrine\DBAL\Exception $e) {
    $detectedIps = [];
}
try {
    $activeBansDetailed = $dbHandler->getActiveBansDetailed();
} catch (\Doctrine\DBAL\Exception $e) {
    $activeBansDetailed = [];
}

?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Baluarte Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet" type="text/css" />
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        darkbg: '#08121c',
                    }
                }
            }
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            background-color: #08121c !important;
        }
        .navbar {
            background-color: rgba(13, 25, 39, 0.8) !important;
            backdrop-filter: blur(8px);
        }
    </style>
</head>
<body class="min-h-screen text-gray-200">
<div class="navbar shadow-lg mb-8 border-b border-gray-800">
    <div class="flex-1 px-2 mx-2">
        <img src="assets/img/logo.jpg" alt="Baluarte Logo" class="h-10 w-auto mr-2 rounded">
        <span class="text-xl font-bold tracking-tight">Baluarte</span>
    </div>
    <div class="flex-none">
        <ul class="menu menu-horizontal px-1">
            <li><a href="/" class="<?php echo $page === 'dashboard' ? 'active' : ''; ?>">Dashboard</a></li>
            <li><a href="?page=settings" class="<?php echo $page === 'settings' ? 'active' : ''; ?>">Settings</a></li>
            <li><a href="/blocked-ips">Blocked IPs (CSV)</a></li>
        </ul>
    </div>
</div>

<div class="container mx-auto p-4 max-w-6xl">
    <?php if ($page === 'settings'): ?>
        <?php if (isset($_GET['saved'])): ?>
            <div class="alert alert-success mb-6 shadow-lg">
                <i class="fa-solid fa-circle-check"></i>
                <span>Configuration saved successfully!</span>
            </div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="action" value="update_config">
            
            <div class="flex flex-col gap-8 mb-8">
                <!-- General Settings -->
                <div class="card bg-gray-900/50 shadow-xl w-full border border-gray-800">
                    <div class="card-body">
                        <h2 class="card-title mb-4"><i class="fa-solid fa-gears"></i> General Settings</h2>
                        
                        <div class="form-control w-full">
                            <label class="label">
                                <span class="label-text text-gray-300">Database Path</span>
                            </label>
                            <input type="text" name="db_path" value="<?php echo htmlspecialchars($config['database']['path'] ?? 'baluarte.sqlite'); ?>" class="input input-bordered bg-gray-800 border-gray-700 w-full" />
                        </div>

                        <div class="form-control w-full mt-4">
                            <label class="label">
                                <span class="label-text text-gray-300">AbuseIPDB API Key</span>
                            </label>
                            <input type="text" name="abuseipdb_key" value="<?php echo htmlspecialchars($config['api']['abuseipdb']['key'] ?? ''); ?>" class="input input-bordered bg-gray-800 border-gray-700 w-full" />
                        </div>

                        <div class="form-control w-full mt-4">
                            <label class="label">
                                <span class="label-text text-gray-300">GeoIP Database Path</span>
                            </label>
                            <input type="text" name="geoip_path" value="<?php echo htmlspecialchars($config['geoip']['database_path'] ?? ''); ?>" class="input input-bordered bg-gray-800 border-gray-700 w-full" />
                        </div>

                        <div class="form-control w-full mt-4">
                            <label class="label">
                                <span class="label-text text-gray-300">Webhook URL</span>
                            </label>
                            <input type="text" name="webhook_url" value="<?php echo htmlspecialchars($config['notifications']['webhook']['url'] ?? ''); ?>" class="input input-bordered bg-gray-800 border-gray-700 w-full" />
                        </div>

                        <div class="divider before:bg-gray-800 after:bg-gray-800">Firewall</div>

                        <div class="form-control">
                            <label class="label cursor-pointer">
                                <span class="label-text text-gray-300">Enable Firewall Integration</span> 
                                <input type="checkbox" name="firewall_enabled" class="checkbox checkbox-primary" <?php echo ($config['firewall']['enabled'] ?? false) ? 'checked' : ''; ?> />
                            </label>
                        </div>

                        <div class="form-control w-full mt-2">
                            <label class="label">
                                <span class="label-text text-gray-300">Firewall Driver</span>
                            </label>
                            <select name="firewall_driver" class="select select-bordered bg-gray-800 border-gray-700 w-full text-gray-200">
                                <option value="ufw" <?php echo ($config['firewall']['driver'] ?? '') === 'ufw' ? 'selected' : ''; ?>>UFW</option>
                                <option value="iptables" <?php echo ($config['firewall']['driver'] ?? '') === 'iptables' ? 'selected' : ''; ?>>iptables</option>
                            </select>
                        </div>
                    </div>
                </div>

                <!-- Patterns Management -->
                <div class="card bg-gray-900/50 shadow-xl w-full border border-gray-800">
                    <div class="card-body">
                        <h2 class="card-title mb-4"><i class="fa-solid fa-list-check"></i> Log Patterns</h2>
                        <div class="overflow-y-auto max-h-[500px] space-y-4">
                            <?php foreach ($config['patterns'] ?? [] as $id => $pattern): ?>
                                <?php $isEnabled = $pattern['enabled'] ?? true; ?>
                                <div class="<?php echo $isEnabled ? 'bg-success/5 border border-success/20' : 'bg-gray-800/50 border border-gray-700'; ?> p-4 rounded-lg relative group">
                                    <div class="flex justify-between items-start mb-2 pr-8">
                                        <div class="font-bold"><?php echo htmlspecialchars($id); ?></div>
                                        <div class="form-control">
                                            <label class="label cursor-pointer py-0">
                                                <span class="label-text-alt mr-2">Enabled</span>
                                                <input type="checkbox" name="patterns[<?php echo htmlspecialchars($id); ?>][enabled]" class="checkbox checkbox-xs checkbox-primary" <?php echo $isEnabled ? 'checked' : ''; ?> />
                                            </label>
                                        </div>
                                    </div>
                                    <div class="form-control w-full">
                                        <label class="label py-1">
                                            <span class="label-text-alt">Regex</span>
                                        </label>
                                        <input type="text" name="patterns[<?php echo htmlspecialchars($id); ?>][regex]" value="<?php echo htmlspecialchars($pattern['regex']); ?>" class="input input-bordered input-sm w-full" />
                                    </div>
                                    <div class="form-control w-full mt-2">
                                        <label class="label py-1">
                                            <span class="label-text-alt">Reason</span>
                                        </label>
                                        <input type="text" name="patterns[<?php echo htmlspecialchars($id); ?>][reason]" value="<?php echo htmlspecialchars($pattern['reason'] ?? ''); ?>" class="input input-bordered input-sm w-full" />
                                    </div>
                                    <div class="grid grid-cols-2 gap-2 mt-2">
                                        <div class="form-control">
                                            <label class="label py-1">
                                                <span class="label-text-alt">Format (optional)</span>
                                            </label>
                                            <input type="text" name="patterns[<?php echo htmlspecialchars($id); ?>][format]" value="<?php echo htmlspecialchars($pattern['format'] ?? ''); ?>" placeholder="json" class="input input-bordered input-sm w-full" />
                                        </div>
                                        <div class="form-control">
                                            <label class="label py-1">
                                                <span class="label-text-alt">Field (optional)</span>
                                            </label>
                                            <input type="text" name="patterns[<?php echo htmlspecialchars($id); ?>][field]" value="<?php echo htmlspecialchars($pattern['field'] ?? ''); ?>" placeholder="log" class="input input-bordered input-sm w-full" />
                                        </div>
                                    </div>
                                    <button type="button" class="btn btn-circle btn-xs btn-error absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity" onclick="this.closest('.bg-base-200').remove()">
                                        <i class="fa-solid fa-xmark"></i>
                                    </button>
                                </div>
                            <?php endforeach; ?>
                        </div>

                        <div class="divider">Add New Pattern</div>
                        <div class="bg-primary/5 p-4 rounded-lg border border-primary/20">
                            <div class="form-control w-full">
                                <label class="label py-1">
                                    <span class="label-text-alt font-bold">Unique ID</span>
                                </label>
                                <input type="text" name="new_pattern_id" placeholder="e.g. nginx_404" class="input input-bordered input-sm w-full" />
                            </div>
                            <div class="form-control w-full mt-2">
                                <label class="label py-1">
                                    <span class="label-text-alt font-bold">Regex</span>
                                </label>
                                <input type="text" name="new_pattern_regex" placeholder="/regex here/" class="input input-bordered input-sm w-full" />
                            </div>
                            <div class="form-control w-full mt-2">
                                <label class="label py-1">
                                    <span class="label-text-alt font-bold">Reason</span>
                                </label>
                                <input type="text" name="new_pattern_reason" placeholder="What to show in dashboard" class="input input-bordered input-sm w-full" />
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="flex justify-center mb-12">
                <button type="submit" class="btn btn-primary btn-lg px-12 shadow-xl">
                    <i class="fa-solid fa-floppy-disk"></i> Save All Settings
                </button>
            </div>
        </form>

    <?php else: ?>
    
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <!-- Stats -->
        <div class="stats shadow bg-gray-900/50 lg:col-span-3 border border-gray-800">
            <div class="stat border-gray-800">
                <div class="stat-figure text-primary">
                    <i class="fa-solid fa-user-slash fa-2x"></i>
                </div>
                <div class="stat-title text-gray-400">Active Bans</div>
                <div class="stat-value text-primary"><?php echo count($activeBansDetailed); ?></div>
                <div class="stat-desc text-gray-500">Total IPs, ranges, and countries</div>
            </div>
            
            <div class="stat border-gray-800">
                <div class="stat-figure text-secondary">
                    <i class="fa-solid fa-eye fa-2x"></i>
                </div>
                <div class="stat-title text-gray-400">Recent Detections</div>
                <div class="stat-value text-secondary"><?php echo count($detectedIps); ?></div>
                <div class="stat-desc text-gray-500">In the malicious logs database</div>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <!-- Add Ban Form -->
        <div class="card bg-gray-900/50 shadow-xl border border-gray-800">
            <div class="card-body">
                <h2 class="card-title mb-4 text-gray-200">Manual Ban</h2>
                <form method="POST">
                    <input type="hidden" name="action" value="add_ban">
                    <div class="form-control w-full">
                        <label class="label">
                            <span class="label-text text-gray-300">Ban Type</span>
                        </label>
                        <select name="type" class="select select-bordered bg-gray-800 border-gray-700 w-full text-gray-200" id="ban_type" onchange="toggleBanInput()">
                            <option value="ip">Single IP</option>
                            <option value="range">IP Range (CIDR)</option>
                            <option value="country">Country</option>
                        </select>
                    </div>

                    <div class="form-control w-full mt-4" id="target_input_container">
                        <label class="label">
                            <span class="label-text text-gray-300" id="target_label">IP Address</span>
                        </label>
                        <input type="text" name="target" id="target_input" placeholder="e.g. 1.2.3.4" class="input input-bordered bg-gray-800 border-gray-700 w-full text-gray-200" />
                    </div>

                    <div class="form-control w-full mt-4 hidden" id="country_input_container">
                        <label class="label">
                            <span class="label-text text-gray-300">Select Country</span>
                        </label>
                        <select name="target_country" id="country_select" class="select select-bordered bg-gray-800 border-gray-700 w-full text-gray-200">
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
                            <span class="label-text text-gray-300">Duration (minutes)</span>
                        </label>
                        <input type="number" name="duration" value="1440" class="input input-bordered bg-gray-800 border-gray-700 w-full text-gray-200" />
                        <label class="label">
                            <span class="label-text-alt text-gray-500">1440 = 24 hours</span>
                        </label>
                    </div>

                    <div class="card-actions justify-end mt-6">
                        <button type="submit" class="btn btn-primary w-full">Add Ban</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Active Bans Table -->
        <div class="card bg-gray-900/50 shadow-xl lg:col-span-2 border border-gray-800">
            <div class="card-body">
                <h2 class="card-title mb-4 text-gray-200">Currently Blocked</h2>
                <div class="overflow-x-auto">
                    <table class="table w-full">
                        <thead class="text-gray-400 border-gray-800">
                        <tr>
                            <th class="bg-transparent border-gray-800">Target</th>
                            <th class="bg-transparent border-gray-800">Type</th>
                            <th class="bg-transparent border-gray-800">Banned At</th>
                            <th class="bg-transparent border-gray-800">Expires At</th>
                            <th class="bg-transparent border-gray-800">Action</th>
                        </tr>
                        </thead>
                        <tbody class="text-gray-300">
                        <?php foreach ($activeBansDetailed as $ban): ?>
                            <tr class="border-gray-800">
                                <td class="border-gray-800">
                                    <?php if ($ban['type'] === 'country'): ?>
                                        <?php 
                                            $countryCode = $ban['ip_address'];
                                            $found = array_filter($countriesList, fn($c) => $c['code'] === $countryCode);
                                            $country = reset($found);
                                            echo ($country['flag'] ?? '') . ' ' . htmlspecialchars($country['name'] ?? $countryCode);
                                        ?>
                                    <?php else: ?>
                                        <code class="text-sm bg-gray-800 px-2 py-1 rounded text-primary-content/80"><?php echo htmlspecialchars($ban['ip_address']); ?></code>
                                    <?php endif; ?>
                                </td>
                                <td class="border-gray-800">
                                    <div class="badge <?php 
                                        echo match($ban['type']) {
                                            'range' => 'badge-warning',
                                            'country' => 'badge-error',
                                            default => 'badge-ghost border-gray-700'
                                        };
                                    ?>">
                                        <?php echo htmlspecialchars($ban['type']); ?>
                                    </div>
                                </td>
                                <td class="text-xs border-gray-800"><?php echo htmlspecialchars($ban['banned_at']); ?></td>
                                <td class="text-xs border-gray-800"><?php echo htmlspecialchars($ban['expires_at']); ?></td>
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
        <div class="card bg-gray-900/50 shadow-xl lg:col-span-3 border border-gray-800">
            <div class="card-body">
                <h2 class="card-title mb-4 text-gray-200">Recent Detections</h2>
                <div class="overflow-x-auto">
                    <table class="table w-full">
                        <thead class="text-gray-400 border-gray-800">
                        <tr>
                            <th class="bg-transparent border-gray-800">IP Address</th>
                            <th class="bg-transparent border-gray-800">Reason</th>
                            <th class="bg-transparent border-gray-800">Source</th>
                            <th class="bg-transparent border-gray-800">Location</th>
                            <th class="bg-transparent border-gray-800">Detected At</th>
                        </tr>
                        </thead>
                        <tbody class="text-gray-300">
                        <?php foreach ($detectedIps as $ip): ?>
                            <tr class="hover:bg-gray-800/30 border-gray-800 transition-colors">
                                <td class="border-gray-800">
                                    <div class="flex items-center space-x-2">
                                        <code class="text-sm bg-gray-800 px-2 py-1 rounded text-primary-content/80"><?php echo htmlspecialchars($ip['ip_address']); ?></code>
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
                                <td class="max-w-xs truncate border-gray-800" title="<?php echo htmlspecialchars($ip['reason']); ?>">
                                    <?php echo htmlspecialchars($ip['reason']); ?>
                                </td>
                                <td class="border-gray-800"><span class="badge badge-info badge-sm"><?php echo htmlspecialchars($ip['log_source']); ?></span></td>
                                <td class="text-sm border-gray-800">
                                    <?php echo htmlspecialchars(($ip['city'] ?? '') . ($ip['city'] && $ip['country'] ? ', ' : '') . ($ip['country'] ?? '') ?: 'Unknown'); ?>
                                    <?php if ($ip['isp']): ?>
                                        <br><small class="opacity-60"><?php echo htmlspecialchars($ip['isp']); ?></small>
                                    <?php endif; ?>
                                </td>
                                <td class="text-xs border-gray-800"><?php echo htmlspecialchars($ip['detected_at']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($detectedIps)): ?>
                            <tr><td colspan="5" class="text-center italic opacity-50 border-gray-800">No detections found.</td></tr>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>
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
