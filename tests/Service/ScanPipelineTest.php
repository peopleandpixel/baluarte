<?php

declare(strict_types=1);

namespace Baluarte\Tests\Service;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Scanner\DnsblServiceInterface;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Scanner\GeoIpServiceInterface;
use Baluarte\Scanner\LogScanner;
use Baluarte\Scanner\NotificationManager;
use Baluarte\Scanner\WhitelistManager;
use Baluarte\Service\Configuration;
use Baluarte\Service\ScanService;
use Baluarte\Service\Firewall\FirewallDriverInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface as ComponentEventDispatcher;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface as ContractsEventDispatcher;

class ScanPipelineTest extends TestCase
{
    private string $dbFile;
    private DatabaseHandler $db;
    private ArrayAdapter $cache;

    /** @var ComponentEventDispatcher&MockObject */
    private ComponentEventDispatcher $dispatcher;

    protected function setUp(): void
    {
        $this->dbFile = sys_get_temp_dir() . '/baluarte_test_' . uniqid() . '.sqlite';
        $this->db = new DatabaseHandler($this->dbFile, new NullLogger(), $this->createStub(ContractsEventDispatcher::class));
        $this->cache = new ArrayAdapter();
        $this->dispatcher = $this->createMock(ComponentEventDispatcher::class);
    }

    protected function tearDown(): void
    {
        if (is_file($this->dbFile)) {
            @unlink($this->dbFile);
        }
    }

    private function makeScanService(
        FirewallDriverInterface $driver,
        array $config = [],
        array $fakeGeo = ['country' => 'Neverland', 'country_code' => 'NV', 'city' => 'Nowhere', 'isp' => 'TestISP'],
        array $fakeRepByIp = [],
        array $fakeDnsblByIp = [],
        array $whitelistedIps = []
    ): ScanService {
        $logger = new NullLogger();

        $scanner = new LogScanner([], $logger);
        $firewallManager = new FirewallManager(true, [$driver]);
        $notification = new NotificationManager([]); // disabled notifications

        $whitelist = new WhitelistManager($whitelistedIps);

        $geoIp = $this->createStub(GeoIpServiceInterface::class);
        $geoIp->method('lookup')->willReturnCallback(fn(string $ip) => $fakeGeo);

        $reputation = new class($fakeRepByIp) implements \Baluarte\Scanner\ReputationCheckerInterface {
            public function __construct(private array $rep) {}
            public function checkIp(string $ip): array { return $this->rep[$ip] ?? []; }
            public function checkIps(array $ips): array {
                $out = [];
                foreach ($ips as $ip) { $out[$ip] = $this->rep[$ip] ?? []; }
                return $out;
            }
        };

        $dnsbl = $this->createStub(DnsblServiceInterface::class);
        $dnsbl->method('checkIp')->willReturn([]);
        $dnsbl->method('checkIps')->willReturnCallback(function(array $ips) use ($fakeDnsblByIp) {
            $out = [];
            foreach ($ips as $ip) { $out[$ip] = $fakeDnsblByIp[$ip] ?? []; }
            return $out;
        });

        // Use provided config with sensible defaults
        $config = new Configuration(array_replace_recursive([
            'threshold' => ['attempts' => 1, 'minutes' => 60],
            'ban_duration' => 60,
            'log_format' => 'plain',
        ], $config));

        return new ScanService(
            $scanner,
            $this->db,
            $reputation,
            $firewallManager,
            $notification,
            $whitelist,
            $geoIp,
            $dnsbl,
            $this->dispatcher,
            $logger,
            $this->cache,
            $config
        );
    }

    private function writeLog(string $content): string
    {
        $file = sys_get_temp_dir() . '/baluarte_log_' . uniqid() . '.log';
        file_put_contents($file, $content);
        return $file;
    }

    public function test_simple_block_flow_through_scanFile(): void
    {
        $driver = new TestFirewallDriver();
        $service = $this->makeScanService($driver, [
            'threshold' => ['attempts' => 1, 'minutes' => 60],
            'ban_duration' => 15,
        ]);

        $line = 'Jan  1 00:00:00 host sshd[111]: Failed password for invalid user admin from 10.20.30.40 port 22 ssh2';
        $log = $this->writeLog($line . "\n");

        $saved = $service->scanFile($log, batchSize: 10);
        $this->assertSame(1, $saved, 'One detection should be saved');

        // Firewall should receive the block
        $this->assertSame(['10.20.30.40'], $driver->blocked, 'Firewall driver should be called to block IP');

        // DB should contain the ban
        $this->assertContains('10.20.30.40', $this->db->getActiveBans());
    }

    public function test_threshold_respected_across_multiple_hits(): void
    {
        $driver = new TestFirewallDriver();
        $service = $this->makeScanService($driver, [
            'threshold' => ['attempts' => 3, 'minutes' => 60],
            'ban_duration' => 60,
        ]);

        $ip = '23.34.45.56';
        $line = 'Jan  1 00:00:00 host sshd[111]: Failed password for invalid user admin from ' . $ip . ' port 22 ssh2';
        $log = $this->writeLog($line . "\n" . $line . "\n" . $line . "\n");

        $saved = $service->scanFile($log, batchSize: 100);
        $this->assertSame(1, $saved, 'Duplicate reasons for same IP are stored once');

        // Should be blocked only once; threshold reached
        $this->assertContains($ip, $driver->blocked);
        $this->assertContains($ip, $this->db->getActiveBans());
    }

    public function test_dry_run_records_ban_without_firewall_call(): void
    {
        $driver = new TestFirewallDriver();
        $service = $this->makeScanService($driver, [
            'threshold' => ['attempts' => 1, 'minutes' => 60],
            'ban_duration' => 5,
        ]);
        $service->setDryRun(true);

        $ip = '66.77.88.99';
        $line = 'Jan  1 00:00:00 host sshd[111]: Failed password for invalid user admin from ' . $ip . ' port 22 ssh2';
        $log = $this->writeLog($line . "\n");

        $service->scanFile($log, batchSize: 10);
        // No firewall call expected
        $this->assertSame([], $driver->blocked);
        // But ban is recorded in DB
        $this->assertContains($ip, $this->db->getActiveBans());
    }

    public function test_whitelisted_ip_is_skipped(): void
    {
        // Custom driver that would record blocks if any
        $driver = new TestFirewallDriver();

        // Build service with whitelist containing the target IP
        $service = $this->makeScanService($driver, whitelistedIps: ['77.1.2.3']);

        $ip = '77.1.2.3';
        $line = 'Jan  1 00:00:00 host sshd[111]: Failed password for invalid user admin from ' . $ip . ' port 22 ssh2';
        $log = $this->writeLog($line . "\n");

        $saved = $service->scanFile($log, batchSize: 10);

        // Nothing saved nor blocked
        $this->assertSame(0, $saved, 'Whitelisted IP should be ignored');
        $this->assertSame([], $driver->blocked, 'No firewall call for whitelisted IP');
        $this->assertNotContains($ip, $this->db->getActiveBans());
    }
}

class TestFirewallDriver implements FirewallDriverInterface
{
    public array $blocked = [];
    public array $unblocked = [];

    public function blockIp(string $ip): bool
    {
        $this->blocked[] = $ip;
        return true;
    }

    public function unblockIp(string $ip): bool
    {
        $this->unblocked[] = $ip;
        return true;
    }

    public function blockRange(string $target): bool { return true; }
    public function unblockRange(string $target): bool { return true; }
    public function getName(): string { return 'test'; }
}
