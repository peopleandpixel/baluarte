#!/usr/bin/env php
<?php

require __DIR__ . '/vendor/autoload.php';

use Baluarte\Command\ScanCommand;
use Baluarte\Command\ServeCommand;
use Baluarte\Database\DatabaseHandler;
use Baluarte\Service\Firewall\IptablesDriver;
use Baluarte\Service\Firewall\NftablesDriver;
use Baluarte\Service\Firewall\UfwDriver;
use Baluarte\Subscriber\LoggerSubscriber;
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
    ->addArgument(new Reference('logger'));

// LogScanner
$containerBuilder->register('log_scanner', LogScanner::class)
    ->addArgument($config['patterns'] ?? [])
    ->addArgument(new Reference('logger'));

// ReputationChecker
$containerBuilder->register('reputation_checker', ReputationChecker::class)
    ->addArgument($config['api']['abuseipdb']['key'] ?? null);

// Firewall Driver
$firewallDriverType = $config['firewall']['driver'] ?? 'ufw';
switch ($firewallDriverType) {
    case 'iptables':
        $containerBuilder->register('firewall_driver', IptablesDriver::class);
        break;
    case 'nftables':
        $containerBuilder->register('firewall_driver', NftablesDriver::class);
        break;
    case 'ufw':
    default:
        $containerBuilder->register('firewall_driver', UfwDriver::class);
        break;
}

// FirewallManager
$containerBuilder->register('firewall_manager', FirewallManager::class)
    ->addArgument($config['firewall']['enabled'] ?? false)
    ->addArgument(new Reference('firewall_driver'));

// NotificationManager
$containerBuilder->register('notification_manager', NotificationManager::class)
    ->addArgument($config['notifications'] ?? []);

// WhitelistManager
$containerBuilder->register('whitelist_manager', \Baluarte\Scanner\WhitelistManager::class)
    ->addArgument($config['whitelist'] ?? []);

// GeoIpService
$containerBuilder->register('geoip_service', \Baluarte\Scanner\GeoIpService::class)
    ->addArgument($config['geoip']['database_path'] ?? null)
    ->addArgument(new Reference('logger'));

// Event Dispatcher
$containerBuilder->register('event_dispatcher', EventDispatcher::class)
    ->addMethodCall('addSubscriber', [new Reference('logger_subscriber')]);

$containerBuilder->register('logger_subscriber', LoggerSubscriber::class)
    ->addArgument(new Reference('logger'));

// ScanCommand
$containerBuilder->register('scan_command', ScanCommand::class)
    ->addArgument(new Reference('log_scanner'))
    ->addArgument(new Reference('db_handler'))
    ->addArgument(new Reference('reputation_checker'))
    ->addArgument(new Reference('firewall_manager'))
    ->addArgument(new Reference('notification_manager'))
    ->addArgument(new Reference('whitelist_manager'))
    ->addArgument(new Reference('geoip_service'))
    ->addArgument(new Reference('event_dispatcher'))
    ->addArgument(new Reference('logger'))
    ->addArgument($config['log_format'] ?? 'plain')
    ->addArgument($config['threshold'] ?? ['attempts' => 1, 'minutes' => 60])
    ->addArgument($config['ban_duration'] ?? 1440);

// ServeCommand
$containerBuilder->register('serve_command', ServeCommand::class);

$application = new Application('Baluarte', '1.0.0');
$application->addCommand($containerBuilder->get('scan_command'));
$application->addCommand($containerBuilder->get('serve_command'));
$application->run();
