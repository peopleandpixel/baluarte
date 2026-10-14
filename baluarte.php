#!/usr/bin/env php
<?php

require __DIR__ . '/vendor/autoload.php';

use Baluarte\Service\Configuration;
use Baluarte\Service\Firewall\IptablesDriver;
use Baluarte\Service\Firewall\NftablesDriver;
use Baluarte\Service\Firewall\UfwDriver;
use Monolog\Logger;
use Symfony\Component\Console\Application;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\Yaml\Yaml;

$configPath = __DIR__ . '/config/config.yaml';
$config = [];
if (file_exists($configPath)) {
    $config = Yaml::parseFile($configPath);
}

$containerBuilder = new ContainerBuilder();

// Set parameters from config.yaml
$containerBuilder->setParameter('app_config', $config);
$containerBuilder->setParameter('root_dir', __DIR__);
$containerBuilder->setParameter('log_path', __DIR__ . '/logs/baluarte.log');
$containerBuilder->setParameter('cache_dir', __DIR__ . '/data/cache');
$containerBuilder->setParameter('logging_max_files', $config['logging']['max_files'] ?? 7);
$containerBuilder->setParameter('geoip_database_path', $config['geoip']['database_path'] ?? null);
$containerBuilder->setParameter('abuseipdb_key', $config['api']['abuseipdb']['key'] ?? null);
$containerBuilder->setParameter('dnsbl_config', $config['api']['dnsbl'] ?? []);
$containerBuilder->setParameter('firewall_enabled', $config['firewall']['enabled'] ?? false);
$containerBuilder->setParameter('whitelist_ips', $config['whitelist']['ips'] ?? []);
$containerBuilder->setParameter('whitelist_countries', $config['whitelist']['countries'] ?? []);
$containerBuilder->setParameter('patterns', $config['patterns'] ?? []);
$containerBuilder->setParameter('notifications_config', $config['notifications'] ?? []);
$containerBuilder->setParameter('mqtt_config', $config['notifications']['mqtt'] ?? []);
$containerBuilder->setParameter('mqtt_enabled', $config['notifications']['mqtt']['enabled'] ?? false);
$containerBuilder->setParameter('database_config', $config['database'] ?? ['driver' => 'sqlite', 'path' => 'baluarte.sqlite']);

// Register firewall drivers dynamically based on config (before YAML load)
registerFirewallDrivers($containerBuilder, $config);

// Register cache adapter (dynamic: Redis or Filesystem)
registerCacheAdapter($containerBuilder, $config);

// Load services from YAML configuration
$loader = new YamlFileLoader($containerBuilder, new FileLocator(__DIR__ . '/config'));
$loader->load('services.yaml');

$containerBuilder->compile();

$composerData = json_decode(file_get_contents(__DIR__ . '/composer.json'), true);
$version = $composerData['version'] ?? 'unknown';

$application = new Application('Baluarte', $version);
$commands = [
    'scan_command' => 'scan',
    'serve_command' => 'serve',
    'export_command' => 'export',
    'migrate_command' => 'migrate',
    'mqtt_listen_command' => 'mqtt:listen',
    'honeypot_http_command' => 'honeypot:http',
];
foreach ($commands as $serviceId => $name) {
    try {
        $application->addCommand($containerBuilder->get($serviceId));
    } catch (Exception $e) {
        fwrite(STDERR, "[ERROR] Failed to register command '{$name}': " . $e->getMessage() . "\n");
    }
}
try {
    $application->run();
} catch (Exception $e) {
    fwrite(STDERR, "[ERROR] Application error: " . $e->getMessage() . "\n");
    exit(1);
}

/**
 * Register the appropriate cache adapter based on configuration.
 */
function registerCacheAdapter(ContainerBuilder $container, array $config): void
{
    if (($config['cache']['backend'] ?? 'filesystem') === 'redis') {
        try {
            $redisDsn = $config['cache']['redis']['dsn'] ?? 'redis://localhost:6379';
            $namespace = $config['cache']['namespace'] ?? 'baluarte';
            $defaultLifetime = (int)($config['cache']['default_lifetime'] ?? 0);

            if (class_exists(\Symfony\Component\Cache\Adapter\RedisAdapter::class)) {
                $container->register('cache', \Symfony\Component\Cache\Adapter\RedisAdapter::class)
                    ->addArgument(\Symfony\Component\Cache\Adapter\RedisAdapter::createConnection($redisDsn))
                    ->addArgument($namespace)
                    ->addArgument($defaultLifetime);
                return;
            }
        } catch (\Throwable $e) {
            // Fallback to filesystem
        }
    }

    $container->register('cache', \Symfony\Component\Cache\Adapter\FilesystemAdapter::class)
        ->addArgument('baluarte')
        ->addArgument(0)
        ->addArgument($container->getParameter('cache_dir'));
}

/**
 * Register firewall drivers and manager based on configuration.
 */
function registerFirewallDrivers(ContainerBuilder $container, array $config): void
{
    $firewallDrivers = [];
    $configuredDrivers = $config['firewall']['drivers'] ?? [$config['firewall']['driver'] ?? 'ufw'];

    $driverClasses = [
        'iptables' => IptablesDriver::class,
        'nftables' => NftablesDriver::class,
        'ufw' => UfwDriver::class,
    ];

    foreach ($configuredDrivers as $driverType) {
        $driverId = 'firewall_driver.' . $driverType;
        $class = $driverClasses[$driverType] ?? UfwDriver::class;
        $container->register($driverId, $class);
        $firewallDrivers[] = new Reference($driverId);
    }

    // Register FirewallManager with the dynamic driver references
    $container->register('firewall_manager', \Baluarte\Scanner\FirewallManager::class)
        ->addArgument($config['firewall']['enabled'] ?? false)
        ->addArgument($firewallDrivers)
        ->setPublic(true);
}
