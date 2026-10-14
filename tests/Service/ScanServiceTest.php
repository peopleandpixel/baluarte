<?php

namespace Baluarte\Tests\Service;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Event\ThreatDetectedEvent;
use Baluarte\Scanner\DnsblServiceInterface;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Scanner\GeoIpServiceInterface;
use Baluarte\Scanner\LogScanner;
use Baluarte\Scanner\NotificationManager;
use Baluarte\Scanner\ReputationCheckerInterface;
use Baluarte\Scanner\WhitelistManager;
use Baluarte\Service\Configuration;
use Baluarte\Service\ScanService;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Contracts\Cache\CacheInterface;

#[AllowMockObjectsWithoutExpectations]
class ScanServiceTest extends TestCase
{
    private ScanService $service;
    private LogScanner $scanner;
    private DatabaseHandler $db;
    private ReputationCheckerInterface $reputationChecker;
    private FirewallManager $firewallManager;
    private NotificationManager $notificationManager;
    private WhitelistManager $whitelistManager;
    private GeoIpServiceInterface $geoIpService;
    private DnsblServiceInterface $dnsblService;
    private EventDispatcherInterface $eventDispatcher;
    private LoggerInterface $logger;
    private CacheInterface $cache;
    private Configuration $config;

    protected function setUp(): void
    {
        $this->scanner = $this->createMock(LogScanner::class);
        $this->db = $this->createMock(DatabaseHandler::class);
        $this->reputationChecker = $this->createMock(ReputationCheckerInterface::class);
        $this->firewallManager = $this->createMock(FirewallManager::class);
        $this->notificationManager = $this->createMock(NotificationManager::class);
        $this->whitelistManager = $this->createMock(WhitelistManager::class);
        $this->geoIpService = $this->createMock(GeoIpServiceInterface::class);
        $this->dnsblService = $this->createMock(DnsblServiceInterface::class);
        $this->eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->cache = new ArrayAdapter();
        $this->config = new Configuration([
            'ban_duration' => 1440,
            'threshold' => ['attempts' => 1, 'minutes' => 60],
            'log_format' => 'plain',
            'cleanup_days' => 30,
        ]);

        $this->service = new ScanService(
            $this->scanner,
            $this->db,
            $this->reputationChecker,
            $this->firewallManager,
            $this->notificationManager,
            $this->whitelistManager,
            $this->geoIpService,
            $this->dnsblService,
            $this->eventDispatcher,
            $this->logger,
            $this->cache,
            $this->config
        );
    }

    public function testScanFileReturnsZeroWhenNoHits(): void
    {
        $this->scanner->expects($this->once())
            ->method('scanFile')
            ->willReturnCallback(function () {
                return (function () {
                    yield from [];
                })();
            });

        $this->db->expects($this->once())
            ->method('getSetting')
            ->with('offset_' . md5('/var/log/auth.log'), '0')
            ->willReturn('0');

        $this->db->expects($this->once())
            ->method('setSetting');

        $result = $this->service->scanFile('/var/log/auth.log');
        $this->assertEquals(0, $result);
    }

    public function testScanFileProcessesHits(): void
    {
        $hits = [
            ['ip' => '10.0.0.1', 'reason' => 'Failed password', 'source' => 'sshd'],
        ];

        $this->scanner->expects($this->once())
            ->method('scanFile')
            ->willReturnCallback(function () use ($hits) {
                return (function () use ($hits) {
                    yield from $hits;
                })();
            });

        $this->db->expects($this->once())
            ->method('getSetting')
            ->willReturn('0');

        $this->whitelistManager->method('isWhitelisted')->willReturn(false);
        $this->whitelistManager->method('isCountryWhitelisted')->willReturn(false);
        $this->reputationChecker->method('checkIps')->willReturn(['10.0.0.1' => []]);
        $this->dnsblService->method('checkIps')->willReturn(['10.0.0.1' => []]);
        $this->geoIpService->method('lookupIps')->willReturn(['10.0.0.1' => ['country_code' => 'US']]);
        $this->db->method('getAttemptCount')->willReturn(0);
        $this->firewallManager->method('blockIp')->willReturn(true);
        $this->db->method('saveIps')->willReturn(1);

        $result = $this->service->scanFile('/var/log/auth.log');
        $this->assertEquals(1, $result);
    }

    public function testProcessHitsSkipsWhitelistedIp(): void
    {
        $hits = [
            ['ip' => '192.168.1.1', 'reason' => 'Test', 'source' => 'test'],
        ];

        $this->whitelistManager->expects($this->once())
            ->method('isWhitelisted')
            ->with('192.168.1.1')
            ->willReturn(true);

        $this->db->expects($this->never())
            ->method('saveIps');

        $result = $this->service->processHits($hits, '/var/log/auth.log', 100);
        $this->assertEquals(0, $result);
    }

    public function testProcessHitsSkipsWhitelistedCountry(): void
    {
        $hits = [
            ['ip' => '10.0.0.1', 'reason' => 'Test', 'source' => 'test'],
        ];

        $this->whitelistManager->method('isWhitelisted')->willReturn(false);
        $this->whitelistManager->expects($this->once())
            ->method('isCountryWhitelisted')
            ->with('DE')
            ->willReturn(true);
        $this->geoIpService->method('lookupIps')->willReturn(['10.0.0.1' => ['country_code' => 'DE']]);
        $this->reputationChecker->method('checkIps')->willReturn(['10.0.0.1' => []]);
        $this->dnsblService->method('checkIps')->willReturn(['10.0.0.1' => []]);

        $this->db->expects($this->never())
            ->method('saveIps');

        $result = $this->service->processHits($hits, '/var/log/auth.log', 100);
        $this->assertEquals(0, $result);
    }

    public function testProcessHitsDispatchesEventWhenThresholdMet(): void
    {
        $hits = [
            ['ip' => '10.0.0.1', 'reason' => 'Failed password', 'source' => 'sshd'],
        ];

        $this->whitelistManager->method('isWhitelisted')->willReturn(false);
        $this->whitelistManager->method('isCountryWhitelisted')->willReturn(false);
        $this->reputationChecker->method('checkIps')->willReturn(['10.0.0.1' => []]);
        $this->dnsblService->method('checkIps')->willReturn(['10.0.0.1' => []]);
        $this->geoIpService->method('lookupIps')->willReturn(['10.0.0.1' => ['country_code' => 'US']]);
        $this->db->method('getAttemptCount')->willReturn(0);
        $this->firewallManager->method('blockIp')->willReturn(true);
        $this->db->method('saveIps')->willReturn(1);

        $this->eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with(
                $this->isInstanceOf(ThreatDetectedEvent::class),
                ThreatDetectedEvent::NAME
            );

        $this->service->processHits($hits, '/var/log/auth.log', 100);
    }

    public function testProcessHitsDoesNotBlockBelowThreshold(): void
    {
        $this->config = new Configuration([
            'ban_duration' => 1440,
            'threshold' => ['attempts' => 5, 'minutes' => 60],
            'log_format' => 'plain',
        ]);

        $this->service = new ScanService(
            $this->scanner, $this->db, $this->reputationChecker,
            $this->firewallManager, $this->notificationManager,
            $this->whitelistManager, $this->geoIpService, $this->dnsblService,
            $this->eventDispatcher, $this->logger, $this->cache, $this->config
        );

        $hits = [
            ['ip' => '10.0.0.1', 'reason' => 'Failed password', 'source' => 'sshd'],
        ];

        $this->whitelistManager->method('isWhitelisted')->willReturn(false);
        $this->whitelistManager->method('isCountryWhitelisted')->willReturn(false);
        $this->reputationChecker->method('checkIps')->willReturn(['10.0.0.1' => []]);
        $this->dnsblService->method('checkIps')->willReturn(['10.0.0.1' => []]);
        $this->geoIpService->method('lookupIps')->willReturn(['10.0.0.1' => ['country_code' => 'US']]);
        $this->db->method('getAttemptCount')->willReturn(1);

        $this->firewallManager->expects($this->never())
            ->method('blockIp');

        $this->eventDispatcher->expects($this->never())
            ->method('dispatch');

        $this->service->processHits($hits, '/var/log/auth.log', 100);
    }

    public function testSetDryRun(): void
    {
        $this->service->setDryRun(true);
        
        $this->db->expects($this->once())
            ->method('getExpiredBans')
            ->willReturn(['10.0.0.1']);

        $this->firewallManager->expects($this->never())
            ->method('unblockIp');

        $this->logger->expects($this->once())
            ->method('info')
            ->with($this->stringContains('Dry-run'));

        $this->service->unbanExpiredIps();
    }

    public function testUnbanExpiredIps(): void
    {
        $this->db->expects($this->once())
            ->method('getExpiredBans')
            ->willReturn(['10.0.0.1', '10.0.0.2']);

        $this->firewallManager->method('unblockIp')->willReturn(true);

        $result = $this->service->unbanExpiredIps();
        $this->assertEquals(['10.0.0.1', '10.0.0.2'], $result);
    }

    public function testUnbanExpiredIpsHandlesFirewallFailure(): void
    {
        $this->db->expects($this->once())
            ->method('getExpiredBans')
            ->willReturn(['10.0.0.1']);

        $this->firewallManager->method('unblockIp')->willReturn(false);
        $this->db->expects($this->never())
            ->method('removeBan');

        $result = $this->service->unbanExpiredIps();
        $this->assertEquals([], $result);
    }

    public function testUnbanExpiredIpsDryRun(): void
    {
        $this->service->setDryRun(true);

        $this->db->expects($this->once())
            ->method('getExpiredBans')
            ->willReturn(['10.0.0.1']);

        $this->firewallManager->expects($this->never())
            ->method('unblockIp');

        $this->db->expects($this->once())
            ->method('removeBan');

        $result = $this->service->unbanExpiredIps();
        $this->assertEquals(['10.0.0.1'], $result);
    }

    public function testCleanupOldEntries(): void
    {
        $this->db->expects($this->once())
            ->method('cleanup')
            ->with(30)
            ->willReturn(100);

        $result = $this->service->cleanupOldEntries();
        $this->assertEquals(100, $result);
    }

    public function testCleanupOldEntriesSkipsWhenDaysZero(): void
    {
        $this->config = new Configuration([
            'ban_duration' => 1440,
            'threshold' => ['attempts' => 1, 'minutes' => 60],
            'log_format' => 'plain',
            'cleanup_days' => 0,
        ]);

        $this->service = new ScanService(
            $this->scanner, $this->db, $this->reputationChecker,
            $this->firewallManager, $this->notificationManager,
            $this->whitelistManager, $this->geoIpService, $this->dnsblService,
            $this->eventDispatcher, $this->logger, $this->cache, $this->config
        );

        $this->db->expects($this->never())
            ->method('cleanup');

        $result = $this->service->cleanupOldEntries();
        $this->assertEquals(0, $result);
    }

    public function testScanFileDoesNotSaveOffsetForJournald(): void
    {
        $this->scanner->expects($this->once())
            ->method('scanFile')
            ->willReturnCallback(function () {
                return (function () {
                    yield from [];
                })();
            });

        $this->db->expects($this->never())
            ->method('setSetting');

        $this->service->scanFile('journald');
    }
}
