<?php

namespace Baluarte\Tests\Service;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Scanner\WhitelistManager;
use Baluarte\Service\Configuration;
use Baluarte\Service\HoneypotService;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Contracts\Cache\CacheInterface;

#[AllowMockObjectsWithoutExpectations]
class HoneypotServiceTest extends TestCase
{
    private HoneypotService $service;
    private DatabaseHandler $db;
    private FirewallManager $firewall;
    private WhitelistManager $whitelist;
    private LoggerInterface $logger;
    private CacheInterface $cache;
    private Configuration $config;

    protected function setUp(): void
    {
        $this->db = $this->createMock(DatabaseHandler::class);
        $this->firewall = $this->createMock(FirewallManager::class);
        $this->whitelist = $this->createMock(WhitelistManager::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->cache = new ArrayAdapter();
        $this->config = new Configuration([
            'honeypot' => [
                'threshold' => 3,
                'window_minutes' => 5,
                'ban_minutes' => 1440,
                'log_thinning_ttl' => 1,
            ],
        ]);

        $this->service = new HoneypotService(
            $this->db,
            $this->firewall,
            $this->whitelist,
            $this->logger,
            $this->cache,
            $this->config
        );
    }

    public function testRecordHitIgnoresInvalidIp(): void
    {
        $this->db->expects($this->never())
            ->method('saveIp');

        $this->service->recordHit('not-an-ip');
    }

    public function testRecordHitSkipsWhitelistedIp(): void
    {
        $ip = '192.168.1.100';

        $this->whitelist->expects($this->once())
            ->method('isWhitelisted')
            ->with($ip)
            ->willReturn(true);

        $this->db->expects($this->never())
            ->method('saveIp');

        $this->service->recordHit($ip);
    }

    public function testRecordHitSavesIp(): void
    {
        $ip = '10.0.0.1';

        $this->whitelist->expects($this->once())
            ->method('isWhitelisted')
            ->with($ip)
            ->willReturn(false);

        $this->db->expects($this->once())
            ->method('saveIp')
            ->with($ip, 'honeypot', 'honeypot', []);

        $this->db->expects($this->once())
            ->method('getAttemptCount')
            ->with($ip, 5)
            ->willReturn(0);

        $this->service->recordHit($ip);
    }

    public function testRecordHitBansAfterThreshold(): void
    {
        $ip = '10.0.0.2';

        $this->whitelist->expects($this->once())
            ->method('isWhitelisted')
            ->with($ip)
            ->willReturn(false);

        $this->db->expects($this->atLeastOnce())
            ->method('saveIp');

        $this->db->expects($this->once())
            ->method('getAttemptCount')
            ->with($ip, 5)
            ->willReturn(3);

        $this->firewall->expects($this->once())
            ->method('blockIp')
            ->with($ip)
            ->willReturn(true);

        $this->db->expects($this->once())
            ->method('addBan')
            ->with($ip, 1440, 'ip');

        $this->service->recordHit($ip);
    }

    public function testRecordHitDoesNotBanOnFirewallFailure(): void
    {
        $ip = '10.0.0.3';

        $this->whitelist->expects($this->once())
            ->method('isWhitelisted')
            ->with($ip)
            ->willReturn(false);

        $this->db->expects($this->atLeastOnce())
            ->method('saveIp');

        $this->db->expects($this->once())
            ->method('getAttemptCount')
            ->with($ip, 5)
            ->willReturn(5);

        $this->firewall->expects($this->once())
            ->method('blockIp')
            ->with($ip)
            ->willReturn(false);

        $this->db->expects($this->never())
            ->method('addBan');

        $this->service->recordHit($ip);
    }

    public function testRecordHitBelowThreshold(): void
    {
        $ip = '10.0.0.4';

        $this->whitelist->expects($this->once())
            ->method('isWhitelisted')
            ->with($ip)
            ->willReturn(false);

        $this->db->expects($this->atLeastOnce())
            ->method('saveIp');

        $this->db->expects($this->once())
            ->method('getAttemptCount')
            ->with($ip, 5)
            ->willReturn(1);

        $this->firewall->expects($this->never())
            ->method('blockIp');

        $this->db->expects($this->never())
            ->method('addBan');

        $this->service->recordHit($ip);
    }

    public function testRecordHitWithCustomSource(): void
    {
        $ip = '10.0.0.5';

        $this->whitelist->expects($this->once())
            ->method('isWhitelisted')
            ->with($ip)
            ->willReturn(false);

        $this->db->expects($this->once())
            ->method('saveIp')
            ->with($ip, 'honeypot', 'custom-source', []);

        $this->db->expects($this->once())
            ->method('getAttemptCount')
            ->willReturn(0);

        $this->service->recordHit($ip, ['source' => 'custom-source']);
    }

    public function testRecordHitHandlesGetAttemptCountException(): void
    {
        $ip = '10.0.0.6';

        $this->whitelist->expects($this->once())
            ->method('isWhitelisted')
            ->with($ip)
            ->willReturn(false);

        $this->db->expects($this->atLeastOnce())
            ->method('saveIp');

        $this->db->expects($this->once())
            ->method('getAttemptCount')
            ->willThrowException(new \RuntimeException('DB error'));

        $this->firewall->expects($this->never())
            ->method('blockIp');

        $this->service->recordHit($ip);
    }
}
