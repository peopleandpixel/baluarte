<?php

namespace Baluarte\Tests\Service;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Scanner\WhitelistManager;
use Baluarte\Service\Configuration;
use Baluarte\Service\HoneypotService;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class HoneypotServiceExtendedTest extends TestCase
{
    public function testRecordHitIgnoresInvalidIp(): void
    {
        $db = $this->createStub(DatabaseHandler::class);
        $firewall = $this->createStub(FirewallManager::class);
        $whitelist = $this->createStub(WhitelistManager::class);
        $logger = $this->createStub(LoggerInterface::class);
        $cache = new ArrayAdapter();
        $config = new Configuration(['honeypot' => []]);

        $service = new HoneypotService($db, $firewall, $whitelist, $logger, $cache, $config);

        // Should not throw
        $service->recordHit('not-an-ip');
        $this->assertTrue(true); // Verify no exception was thrown
    }

    public function testRecordHitIgnoresWhitelistedIp(): void
    {
        $db = $this->createStub(DatabaseHandler::class);
        $firewall = $this->createStub(FirewallManager::class);
        $whitelist = $this->createMock(WhitelistManager::class);
        $whitelist->expects($this->once())
            ->method('isWhitelisted')
            ->with('192.168.1.1')
            ->willReturn(true);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('info');

        $cache = new ArrayAdapter();
        $config = new Configuration(['honeypot' => []]);

        $service = new HoneypotService($db, $firewall, $whitelist, $logger, $cache, $config);
        $service->recordHit('192.168.1.1');
    }

    public function testRecordHitSavesIpForNonWhitelisted(): void
    {
        $db = $this->createMock(DatabaseHandler::class);
        $db->expects($this->once())
            ->method('saveIp')
            ->with('10.0.0.1', 'honeypot', 'honeypot');

        $db->expects($this->once())
            ->method('getAttemptCount')
            ->willReturn(1);

        $firewall = $this->createStub(FirewallManager::class);
        $whitelist = $this->createStub(WhitelistManager::class);
        $whitelist->method('isWhitelisted')->willReturn(false);

        $logger = $this->createStub(LoggerInterface::class);
        $cache = new ArrayAdapter();
        $config = new Configuration(['honeypot' => ['threshold' => 3]]);

        $service = new HoneypotService($db, $firewall, $whitelist, $logger, $cache, $config);
        $service->recordHit('10.0.0.1');
    }

    public function testRecordHitBansIpWhenThresholdReached(): void
    {
        $db = $this->createMock(DatabaseHandler::class);
        $db->expects($this->once())->method('saveIp');
        $db->expects($this->once())
            ->method('getAttemptCount')
            ->willReturn(5);

        $firewall = $this->createMock(FirewallManager::class);
        $firewall->expects($this->once())
            ->method('blockIp')
            ->with('10.0.0.1')
            ->willReturn(true);

        $db->expects($this->once())
            ->method('addBan')
            ->with('10.0.0.1', 1440, 'ip');

        $whitelist = $this->createStub(WhitelistManager::class);
        $whitelist->method('isWhitelisted')->willReturn(false);

        $logger = $this->createStub(LoggerInterface::class);
        $cache = new ArrayAdapter();
        $config = new Configuration(['honeypot' => ['threshold' => 3, 'ban_minutes' => 1440]]);

        $service = new HoneypotService($db, $firewall, $whitelist, $logger, $cache, $config);
        $service->recordHit('10.0.0.1');
    }

    public function testRecordHitHandlesGetAttemptCountException(): void
    {
        $db = $this->createMock(DatabaseHandler::class);
        $db->expects($this->once())->method('saveIp');
        $db->expects($this->once())
            ->method('getAttemptCount')
            ->willThrowException(new \RuntimeException('DB error'));

        $firewall = $this->createStub(FirewallManager::class);
        $whitelist = $this->createStub(WhitelistManager::class);
        $whitelist->method('isWhitelisted')->willReturn(false);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('error');

        $cache = new ArrayAdapter();
        $config = new Configuration(['honeypot' => []]);

        $service = new HoneypotService($db, $firewall, $whitelist, $logger, $cache, $config);

        // Should not throw
        $service->recordHit('10.0.0.1');
    }
}
