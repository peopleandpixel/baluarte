<?php

namespace Baluarte\Http\Controller;

use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Providers\Qr\GoogleChartsQrCodeProvider;
use RobThree\Auth\TwoFactorAuthException;
use Symfony\Component\Yaml\Yaml;

/**
 * Handles the settings page and configuration updates.
 */
class SettingsController extends BaseController
{
    public function handle(): void
    {
        $this->requireAuth();

        $this->render('settings.latte', [
            'page' => 'settings',
            'detectedIps' => '[]',
            'detectedIpsCount' => 0,
            'activeBansDetailed' => [],
            'activeBansCount' => 0,
            'countriesList' => $this->countriesList,
            'qrCode' => $this->getQrCode(),
            'twoFactorSecret' => $this->config['gui']['two_factor_secret'] ?? null,
            'ipDetails' => null,
        ]);
    }

    public function updateConfig(): void
    {
        $this->requireAuth();

        $newConfig = $this->config;

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

        $configPath = __DIR__ . '/../../../config/config.yaml';
        file_put_contents($configPath, Yaml::dump($newConfig, 4));
        $this->auditLog->logConfigUpdated($this->clientIp);
        $this->redirect('/?page=settings&saved=1');
    }

    public function updateGuiSettings(): void
    {
        $this->requireAuth();

        $newConfig = $this->config;
        if (!isset($newConfig['gui'])) $newConfig['gui'] = [];

        if (!empty($_POST['new_password'])) {
            $newConfig['gui']['password_hash'] = password_hash($_POST['new_password'], PASSWORD_DEFAULT);
        }

        $newConfig['gui']['two_factor_enabled'] = isset($_POST['two_factor_enabled']);
        $newConfig['gui']['theme'] = $_POST['theme'] ?? 'baluarte';

        if (isset($_POST['regenerate_2fa'])) {
            $tfa = new TwoFactorAuth(new GoogleChartsQrCodeProvider());
            $newConfig['gui']['two_factor_secret'] = $tfa->createSecret();
            $newConfig['gui']['two_factor_enabled'] = false;
        }

        $configPath = __DIR__ . '/../../../config/config.yaml';
        file_put_contents($configPath, Yaml::dump($newConfig, 4));
        $this->auditLog->logConfigUpdated($this->clientIp);
        $this->redirect('/?page=settings&saved=1');
    }

    private function getQrCode(): ?string
    {
        $secret = $this->config['gui']['two_factor_secret'] ?? '';
        if (empty($secret)) {
            return null;
        }
        try {
            return (new TwoFactorAuth(new GoogleChartsQrCodeProvider()))
                ->getQRCodeImageAsDataUri('Baluarte', $secret);
        } catch (TwoFactorAuthException $e) {
            return null;
        }
    }
}
