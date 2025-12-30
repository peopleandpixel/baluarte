<?php

require __DIR__ . '/../vendor/autoload.php';

use Baluarte\Database\DatabaseHandler;
use Baluarte\Service\CountryIpService;
use Symfony\Component\Yaml\Yaml;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

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
        $newConfig['api']['jwt_secret'] = $_POST['jwt_secret'] ?? '';
        $newConfig['geoip']['database_path'] = $_POST['geoip_path'] ?? '';
        $newConfig['firewall']['enabled'] = isset($_POST['firewall_enabled']);
        $newConfig['firewall']['driver'] = $_POST['firewall_driver'] ?? 'ufw';
        
        // Logging
        if (!isset($newConfig['logging'])) $newConfig['logging'] = [];
        $newConfig['logging']['max_files'] = (int)($_POST['logging_max_files'] ?? 7);

        // Notifications
        if (!isset($newConfig['notifications'])) $newConfig['notifications'] = [];
        if (!isset($newConfig['notifications']['webhook'])) $newConfig['notifications']['webhook'] = [];
        $newConfig['notifications']['webhook']['url'] = $_POST['webhook_url'] ?? '';
        
        if (!isset($newConfig['notifications']['mqtt'])) $newConfig['notifications']['mqtt'] = [];
        $newConfig['notifications']['mqtt']['enabled'] = isset($_POST['mqtt_enabled']);
        $newConfig['notifications']['mqtt']['host'] = $_POST['mqtt_host'] ?? 'localhost';
        $newConfig['notifications']['mqtt']['port'] = (int)($_POST['mqtt_port'] ?? 1883);
        $newConfig['notifications']['mqtt']['client_id'] = $_POST['mqtt_client_id'] ?? 'baluarte';
        $newConfig['notifications']['mqtt']['username'] = $_POST['mqtt_username'] ?? '';
        $newConfig['notifications']['mqtt']['password'] = $_POST['mqtt_password'] ?? '';
        $newConfig['notifications']['mqtt']['topic_prefix'] = $_POST['mqtt_topic_prefix'] ?? 'baluarte';
        
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

$latte = new Latte\Engine;
$latte->setTempDirectory(__DIR__ . '/../data/cache');

// API Router
if (str_starts_with($uri, '/api/')) {
    header('Content-Type: application/json');
    $method = $_SERVER['REQUEST_METHOD'];
    $path = substr($uri, 5);

    $jwtSecret = $config['api']['jwt_secret'] ?? null;
    if ($jwtSecret) {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!str_starts_with($authHeader, 'Bearer ')) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized: Missing or invalid token format']);
            exit;
        }
        $token = substr($authHeader, 7);
        try {
            JWT::decode($token, new Key($jwtSecret, 'HS256'));
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized: ' . $e->getMessage()]);
            exit;
        }
    }

    try {
        if ($path === 'bans' && $method === 'GET') {
            echo json_encode($dbHandler->getActiveBansDetailed());
            exit;
        }

        if ($path === 'bans' && $method === 'POST') {
            $input = json_decode(file_get_contents('php://temp'), true) ?: $_POST;
            if (empty($input)) {
                $input = json_decode(file_get_contents('php://input'), true) ?: [];
            }
            $target = $input['target'] ?? '';
            $duration = (int)($input['duration'] ?? 1440);
            $type = $input['type'] ?? 'ip';

            if (!$target) {
                http_response_code(400);
                echo json_encode(['error' => 'Target is required']);
                exit;
            }

            $success = $dbHandler->addBan($target, $duration, $type);
            echo json_encode(['success' => $success]);
            exit;
        }

        if (str_starts_with($path, 'bans/') && $method === 'DELETE') {
            $ip = substr($path, 5);
            $success = $dbHandler->removeBan($ip);
            echo json_encode(['success' => $success]);
            exit;
        }

        if ($path === 'threats' && $method === 'GET') {
            $limit = (int)($_GET['limit'] ?? 100);
            echo json_encode($dbHandler->getAllDetectedIps($limit));
            exit;
        }

        if ($path === 'whitelist' && $method === 'GET') {
            echo json_encode($config['whitelist'] ?? []);
            exit;
        }

        if ($path === 'settings' && $method === 'GET') {
            echo json_encode($config);
            exit;
        }

        http_response_code(404);
        echo json_encode(['error' => 'Endpoint not found']);
        exit;
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
        exit;
    }
}

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
    $detectedIps = $dbHandler->getAllDetectedIps(50); // Limit to 50 for performance
    $detectedIpsCount = $dbHandler->getDetectedIpsCount();
} catch (\Doctrine\DBAL\Exception $e) {
    $detectedIps = [];
    $detectedIpsCount = 0;
}
try {
    $activeBansDetailed = $dbHandler->getActiveBansDetailed(50); // Limit to 50 for performance
    $activeBansCount = $dbHandler->getActiveBansCount();
} catch (\Doctrine\DBAL\Exception $e) {
    $activeBansDetailed = [];
    $activeBansCount = 0;
}

$template = match ($page) {
    'settings' => 'settings.latte',
    'bans' => 'bans.latte',
    default => 'dashboard.latte',
};

$latte->render(__DIR__ . '/../templates/' . $template, [
    'page' => $page,
    'config' => $config,
    'detectedIps' => $detectedIps,
    'detectedIpsCount' => $detectedIpsCount,
    'activeBansDetailed' => $activeBansDetailed,
    'activeBansCount' => $activeBansCount,
    'countriesList' => $countriesList,
]);
exit;
