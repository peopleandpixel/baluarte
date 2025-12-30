#!/usr/bin/env php
<?php

require __DIR__ . '/vendor/autoload.php';

use Baluarte\Service\ScanService;
use Baluarte\Service\Configuration;
use Baluarte\Command\ScanCommand;
use Baluarte\Command\ServeCommand;
use Baluarte\Command\ExportCommand;
use Baluarte\Command\MqttListenCommand;
use Baluarte\Database\DatabaseHandler;
use Baluarte\Service\ExportService;
use Baluarte\Service\MqttService;
use Baluarte\Scanner\GeoIpService;
use Baluarte\Scanner\WhitelistManager;
use Baluarte\Service\Firewall\IptablesDriver;
use Baluarte\Service\Firewall\NftablesDriver;
use Baluarte\Service\Firewall\UfwDriver;
use Baluarte\Subscriber\LoggerSubscriber;
use Baluarte\Subscriber\MqttSubscriber;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Scanner\LogScanner;
use Baluarte\Scanner\NotificationManager;
use Baluarte\Scanner\ReputationChecker;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Logger;
use Symfony\Component\Console\Application;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Yaml\Yaml;

$configPath = __DIR__ . '/config/config.yaml';
$config = [];
if (file_exists($configPath)) {
    $config = Yaml::parseFile($configPath);
}

$containerBuilder = new ContainerBuilder();

// Configuration
$containerBuilder->register('config', Configuration::class)
    ->addArgument($config);

// Cache
$containerBuilder->register('cache', FilesystemAdapter::class)
    ->addArgument('baluarte')
    ->addArgument(0)
    ->addArgument(__DIR__ . '/data/cache');

// Logger
$containerBuilder->register('logger', Logger::class)
    ->addArgument('baluarte')
    ->addMethodCall('pushHandler', [new Reference('logger.handler')]);

$containerBuilder->register('logger.handler', RotatingFileHandler::class)
    ->addArgument(__DIR__ . '/logs/baluarte.log')
    ->addArgument($config['logging']['max_files'] ?? 7)
    ->addArgument(Logger::DEBUG);

// DatabaseHandler
$containerBuilder->register('db_handler', DatabaseHandler::class)
    ->addArgument($config['database']['path'] ?? 'baluarte.sqlite')
    ->addArgument(new Reference('logger'))
    ->addArgument(new Reference('event_dispatcher'));

// MQTT Service
$containerBuilder->register('mqtt_service', MqttService::class)
    ->addArgument($config['notifications']['mqtt'] ?? [])
    ->addArgument(new Reference('logger'));

// LogScanner
$containerBuilder->register('log_scanner', LogScanner::class)
    ->addArgument($config['patterns'] ?? [])
    ->addArgument(new Reference('logger'));

// ReputationChecker
$containerBuilder->register('reputation_checker', ReputationChecker::class)
    ->addArgument($config['api']['abuseipdb']['key'] ?? null)
    ->addArgument(new Reference('cache'));

// Firewall Drivers
$firewallDrivers = [];
$configuredDrivers = $config['firewall']['drivers'] ?? [$config['firewall']['driver'] ?? 'ufw'];

foreach ($configuredDrivers as $driverType) {
    $driverId = 'firewall_driver.' . $driverType;
    switch ($driverType) {
        case 'iptables':
            $containerBuilder->register($driverId, IptablesDriver::class);
            break;
        case 'nftables':
            $containerBuilder->register($driverId, NftablesDriver::class);
            break;
        case 'ufw':
        default:
            $containerBuilder->register($driverId, UfwDriver::class);
            break;
    }
    $firewallDrivers[] = new Reference($driverId);
}

// FirewallManager
$containerBuilder->register('firewall_manager', FirewallManager::class)
    ->addArgument($config['firewall']['enabled'] ?? false)
    ->addArgument($firewallDrivers);

// NotificationManager
$containerBuilder->register('notification_manager', NotificationManager::class)
    ->addArgument($config['notifications'] ?? [])
    ->addArgument(new Reference('cache'));

// WhitelistManager
$containerBuilder->register('whitelist_manager', WhitelistManager::class)
    ->addArgument($config['whitelist'] ?? []);

// GeoIpService
$containerBuilder->register('geoip_service', GeoIpService::class)
    ->addArgument($config['geoip']['database_path'] ?? null)
    ->addArgument(new Reference('logger'))
    ->addArgument(new Reference('cache'));

// ExportService
$containerBuilder->register('export_service', ExportService::class);

// Event Dispatcher
$containerBuilder->register('event_dispatcher', EventDispatcher::class)
    ->addMethodCall('addSubscriber', [new Reference('logger_subscriber')])
    ->addMethodCall('addSubscriber', [new Reference('mqtt_subscriber')]);

$containerBuilder->register('logger_subscriber', LoggerSubscriber::class)
    ->addArgument(new Reference('logger'));

$containerBuilder->register('mqtt_subscriber', MqttSubscriber::class)
    ->addArgument(new Reference('mqtt_service'))
    ->addArgument($config['notifications']['mqtt']['enabled'] ?? false);

// ScanService
$containerBuilder->register('scan_service', ScanService::class)
    ->addArgument(new Reference('log_scanner'))
    ->addArgument(new Reference('db_handler'))
    ->addArgument(new Reference('reputation_checker'))
    ->addArgument(new Reference('firewall_manager'))
    ->addArgument(new Reference('notification_manager'))
    ->addArgument(new Reference('whitelist_manager'))
    ->addArgument(new Reference('geoip_service'))
    ->addArgument(new Reference('event_dispatcher'))
    ->addArgument(new Reference('logger'))
    ->addArgument(new Reference('cache'))
    ->addArgument(new Reference('config'));

// ScanCommand
$containerBuilder->register('scan_command', ScanCommand::class)
    ->addArgument(new Reference('scan_service'))
    ->addArgument(new Reference('db_handler'));

// ServeCommand
$containerBuilder->register('serve_command', ServeCommand::class);

// ExportCommand
$containerBuilder->register('export_command', ExportCommand::class)
    ->addArgument(new Reference('db_handler'))
    ->addArgument(new Reference('export_service'));

// MqttListenCommand
$containerBuilder->register('mqtt_listen_command', MqttListenCommand::class)
    ->addArgument(new Reference('mqtt_service'))
    ->addArgument(new Reference('firewall_manager'))
    ->addArgument(new Reference('db_handler'))
    ->addArgument(new Reference('logger'))
    ->addArgument($config['notifications']['mqtt'] ?? []);

$composerData = json_decode(file_get_contents(__DIR__ . '/composer.json'), true);
$version = $composerData['version'] ?? 'unknown';

$application = new Application('Baluarte', $version);
try {
    $application->addCommand($containerBuilder->get('scan_command'));
} catch (Exception $e) {

}
try {
    $application->addCommand($containerBuilder->get('serve_command'));
} catch (Exception $e) {

}
try {
    $application->addCommand($containerBuilder->get('export_command'));
} catch (Exception $e) {

}
try {
    $application->addCommand($containerBuilder->get('mqtt_listen_command'));
} catch (Exception $e) {

}
try {
    $application->run();
} catch (Exception $e) {

}
