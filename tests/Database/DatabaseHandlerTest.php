<?php

namespace Baluarte\Tests\Database;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Event\BanAddedEvent;
use Baluarte\Event\BanRemovedEvent;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class DatabaseHandlerTest extends TestCase
{
    private string $dbPath;
    private DatabaseHandler $db;

    protected function setUp(): void
    {
        $this->dbPath = tempnam(sys_get_temp_dir(), 'db');
        $this->db = new DatabaseHandler($this->dbPath);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->dbPath)) {
            unlink($this->dbPath);
        }
    }

    public function testSaveAndRetrieveIp(): void
    {
        $geoData = ['country' => 'Germany', 'city' => 'Berlin', 'isp' => 'Telekom'];
        $this->db->saveIp('1.1.1.1', 'Test Reason', 'test.log', $geoData);
        $ips = $this->db->getAllDetectedIps();

        $this->assertCount(1, $ips);
        $this->assertEquals('1.1.1.1', $ips[0]['ip']);
        $this->assertEquals('Test Reason', $ips[0]['reason']);
        $this->assertEquals('test.log', $ips[0]['log_source']);
        $this->assertEquals('Germany', $ips[0]['country']);
        $this->assertEquals('Berlin', $ips[0]['city']);
        $this->assertEquals('Telekom', $ips[0]['isp']);
    }

    public function testGetAllDetectedIpsExcludesBanned(): void
    {
        $ip = '1.2.3.4';
        $this->db->saveIp($ip, 'Brute force', 'ssh.log');
        
        // Before ban
        $ips = $this->db->getAllDetectedIps();
        $this->assertCount(1, $ips);
        
        // After ban
        $this->db->addBan($ip, 60);
        $ips = $this->db->getAllDetectedIps();
        $this->assertCount(0, $ips);
        
        // After ban expires (using negative duration for test)
        $this->db->addBan($ip, -1);
        $ips = $this->db->getAllDetectedIps();
        $this->assertCount(1, $ips);
    }

    public function testGetAttemptCount(): void
    {
        $this->db->saveIp('1.2.3.4', 'Reason 1', 'log1');
        $this->db->saveIp('1.2.3.4', 'Reason 2', 'log1');
        
        $count = $this->db->getAttemptCount('1.2.3.4', 60);
        $this->assertEquals(2, $count);
        
        $count = $this->db->getAttemptCount('1.1.1.1', 60);
        $this->assertEquals(0, $count);
    }

    public function testBans(): void
    {
        $ip = '5.5.5.5';
        $this->db->addBan($ip, 60);
        
        $expired = $this->db->getExpiredBans();
        $this->assertNotContains($ip, $expired);
        
        // Add an already expired ban by using a negative duration
        $ipExpired = '6.6.6.6';
        $this->db->addBan($ipExpired, -1);
        
        $expired = $this->db->getExpiredBans();
        $this->assertContains($ipExpired, $expired);
        
        $this->db->removeBan($ipExpired);
        $expired = $this->db->getExpiredBans();
        $this->assertNotContains($ipExpired, $expired);
    }

    public function testGetActiveBans(): void
    {
        $ipActive = '7.7.7.7';
        $ipExpired = '8.8.8.8';

        $this->db->addBan($ipActive, 60);
        $this->db->addBan($ipExpired, -1);

        $active = $this->db->getActiveBans();

        $this->assertContains($ipActive, $active);
        $this->assertNotContains($ipExpired, $active);
    }

    public function testActiveBansDetailed(): void
    {
        $this->db->addBan('1.1.1.1', 60, 'ip');
        $this->db->addBan('192.168.1.0/24', 60, 'range');
        $this->db->addBan('CN', 60, 'country');

        $detailed = $this->db->getActiveBansDetailed();
        $this->assertCount(3, $detailed);

        $types = array_column($detailed, 'type');
        $this->assertContains('ip', $types);
        $this->assertContains('range', $types);
        $this->assertContains('country', $types);
    }

    public function testDuplicateIpReasonIgnored(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test Reason', 'test.log');
        $this->db->saveIp('1.1.1.1', 'Test Reason', 'test.log');
        
        $ips = $this->db->getAllDetectedIps();
        $this->assertCount(1, $ips);
    }

    public function testSaveIpsBulk(): void
    {
        $results = [
            ['ip' => '1.2.3.4', 'reason' => 'Reason 1', 'source' => 'log1'],
            ['ip' => '1.2.3.5', 'reason' => 'Reason 2', 'source' => 'log1'],
            ['ip' => '1.2.3.4', 'reason' => 'Reason 1', 'source' => 'log1'], // Duplicate
        ];

        $count = $this->db->saveIps($results);
        $this->assertEquals(2, $count);
        
        $ips = $this->db->getAllDetectedIps();
        $this->assertCount(2, $ips);
    }

    public function testLogging(): void
    {
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $logger->expects($this->atLeastOnce())
            ->method('info')
            ->with($this->stringContains('Saved 1 new malicious IPs'));

        $db = new DatabaseHandler($this->dbPath, $logger);
        $db->saveIps([['ip' => '9.9.9.9', 'reason' => 'Logging test', 'source' => 'test']]);
    }

    public function testSettings(): void
    {
        $this->db->setSetting('test_key', 'test_value');
        $this->assertEquals('test_value', $this->db->getSetting('test_key'));
        
        $this->db->setSetting('test_key', 'updated_value');
        $this->assertEquals('updated_value', $this->db->getSetting('test_key'));
        
        $this->assertNull($this->db->getSetting('non_existent'));
        $this->assertEquals('default', $this->db->getSetting('non_existent', 'default'));
    }

    public function testCleanup(): void
    {
        $connection = $this->db->getConnection();
        
        // Directly insert old and new entries
        $connection->insert('malicious_ips', [
            'ip_address' => '1.1.1.1',
            'reason' => 'Old',
            'log_source' => 'test',
            'detected_at' => date('Y-m-d H:i:s', strtotime('-31 days'))
        ]);
        $connection->insert('malicious_ips', [
            'ip_address' => '2.2.2.2',
            'reason' => 'New',
            'log_source' => 'test',
            'detected_at' => date('Y-m-d H:i:s', strtotime('-29 days'))
        ]);

        $removed = $this->db->cleanup(30);
        $this->assertEquals(1, $removed);

        $ips = $this->db->getAllDetectedIps();
        $this->assertCount(1, $ips);
        $this->assertEquals('2.2.2.2', $ips[0]['ip']);
    }

    public function testGetDetectedIpsCount(): void
    {
        $this->assertEquals(0, $this->db->getDetectedIpsCount());
        $this->db->saveIp('1.1.1.1', 'Test', 'test.log');
        $this->db->saveIp('2.2.2.2', 'Test', 'test.log');
        $this->assertEquals(2, $this->db->getDetectedIpsCount());
    }

    public function testGetActiveBansCount(): void
    {
        $this->assertEquals(0, $this->db->getActiveBansCount());
        $this->db->addBan('1.1.1.1', 60);
        $this->assertEquals(1, $this->db->getActiveBansCount());
        $this->db->addBan('2.2.2.2', -1); // expired
        $this->assertEquals(1, $this->db->getActiveBansCount());
    }

    public function testGetActiveBansByType(): void
    {
        $this->db->addBan('1.1.1.1', 60, 'ip');
        $this->db->addBan('CN', 60, 'country');
        $this->db->addBan('192.168.1.0/24', 60, 'range');

        $ipBans = $this->db->getActiveBansByType('ip');
        $this->assertContains('1.1.1.1', $ipBans);
        $this->assertNotContains('CN', $ipBans);

        $countryBans = $this->db->getActiveBansByType('country');
        $this->assertContains('CN', $countryBans);
    }

    public function testGetBanDetails(): void
    {
        $this->assertNull($this->db->getBanDetails('1.1.1.1'));

        $this->db->addBan('1.1.1.1', 60, 'ip');
        $details = $this->db->getBanDetails('1.1.1.1');

        $this->assertNotNull($details);
        $this->assertEquals('1.1.1.1', $details['target']);
        $this->assertEquals('ip', $details['type']);
        $this->assertArrayHasKey('banned_at', $details);
        $this->assertArrayHasKey('expires_at', $details);
    }

    public function testGetBanDetailsReturnsNullForExpiredBan(): void
    {
        $this->db->addBan('1.1.1.1', -1); // expired
        $this->assertNull($this->db->getBanDetails('1.1.1.1'));
    }

    public function testGetIpHistory(): void
    {
        $this->db->saveIp('1.1.1.1', 'Reason 1', 'log1');
        $this->db->saveIp('1.1.1.1', 'Reason 2', 'log2');
        $this->db->saveIp('2.2.2.2', 'Reason 3', 'log1');

        $history = $this->db->getIpHistory('1.1.1.1');
        $this->assertCount(2, $history);
        $this->assertEquals('1.1.1.1', $history[0]['ip']);
        $this->assertEquals('1.1.1.1', $history[1]['ip']);

        $history2 = $this->db->getIpHistory('2.2.2.2');
        $this->assertCount(1, $history2);
    }

    public function testGetAllDetectedIpsWithLimit(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test', 'log1');
        $this->db->saveIp('2.2.2.2', 'Test', 'log1');
        $this->db->saveIp('3.3.3.3', 'Test', 'log1');

        $ips = $this->db->getAllDetectedIps(2);
        $this->assertCount(2, $ips);
    }

    public function testSaveIpsEmptyArray(): void
    {
        $count = $this->db->saveIps([]);
        $this->assertEquals(0, $count);
    }

    public function testGetConnection(): void
    {
        $connection = $this->db->getConnection();
        $this->assertInstanceOf(\Doctrine\DBAL\Connection::class, $connection);
    }

    public function testGetLogger(): void
    {
        $logger = $this->db->getLogger();
        $this->assertInstanceOf(LoggerInterface::class, $logger);
    }

    public function testAddBanUpdatesExistingBan(): void
    {
        $this->db->addBan('1.1.1.1', 30);
        $details1 = $this->db->getBanDetails('1.1.1.1');
        
        // Update with longer duration
        $this->db->addBan('1.1.1.1', 120);
        $details2 = $this->db->getBanDetails('1.1.1.1');

        $this->assertNotNull($details1);
        $this->assertNotNull($details2);
        // The expires_at should be different (updated)
        $this->assertNotEquals($details1['expires_at'], $details2['expires_at']);
    }

    public function testRemoveBan(): void
    {
        $this->db->addBan('1.1.1.1', 60);
        $this->assertTrue($this->db->removeBan('1.1.1.1'));
        $this->assertNull($this->db->getBanDetails('1.1.1.1'));
    }

    public function testRemoveNonExistentBan(): void
    {
        // Should return true even if ban doesn't exist (DELETE affects 0 rows)
        $result = $this->db->removeBan('9.9.9.9');
        $this->assertTrue($result);
    }

    public function testEventDispatcherBanAdded(): void
    {
        $dispatcher = new EventDispatcher();
        $banAddedCalled = false;
        $dispatcher->addListener(BanAddedEvent::NAME, function (BanAddedEvent $event) use (&$banAddedCalled) {
            $banAddedCalled = true;
            $this->assertEquals('1.1.1.1', $event->getTarget());
            $this->assertEquals(60, $event->getDuration());
        });

        $db = new DatabaseHandler($this->dbPath, null, $dispatcher);
        $db->addBan('1.1.1.1', 60);
        $this->assertTrue($banAddedCalled);
    }

    public function testEventDispatcherBanRemoved(): void
    {
        $dispatcher = new EventDispatcher();
        $banRemovedCalled = false;
        $dispatcher->addListener(BanRemovedEvent::NAME, function (BanRemovedEvent $event) use (&$banRemovedCalled) {
            $banRemovedCalled = true;
            $this->assertEquals('1.1.1.1', $event->getTarget());
        });

        $db = new DatabaseHandler($this->dbPath, null, $dispatcher);
        $db->addBan('1.1.1.1', 60);
        $db->removeBan('1.1.1.1');
        $this->assertTrue($banRemovedCalled);
    }

    public function testSettingsUpdate(): void
    {
        $this->assertTrue($this->db->setSetting('key1', 'value1'));
        $this->assertEquals('value1', $this->db->getSetting('key1'));
        
        $this->assertTrue($this->db->setSetting('key1', 'updated'));
        $this->assertEquals('updated', $this->db->getSetting('key1'));
    }

    public function testGetExpiredBans(): void
    {
        $this->db->addBan('1.1.1.1', 60); // active
        $this->db->addBan('2.2.2.2', -1); // expired
        $this->db->addBan('3.3.3.3', -1); // expired

        $expired = $this->db->getExpiredBans();
        $this->assertContains('2.2.2.2', $expired);
        $this->assertContains('3.3.3.3', $expired);
        $this->assertNotContains('1.1.1.1', $expired);
    }

    public function testActiveBansDetailedWithLimit(): void
    {
        $this->db->addBan('1.1.1.1', 60);
        $this->db->addBan('2.2.2.2', 60);
        $this->db->addBan('3.3.3.3', 60);

        $detailed = $this->db->getActiveBansDetailed(2);
        $this->assertCount(2, $detailed);
    }

    public function testSaveIpWithoutGeoData(): void
    {
        $this->assertTrue($this->db->saveIp('1.1.1.1', 'Test', 'test.log'));
        $ips = $this->db->getAllDetectedIps();
        $this->assertCount(1, $ips);
        $this->assertNull($ips[0]['country']);
        $this->assertNull($ips[0]['city']);
        $this->assertNull($ips[0]['isp']);
    }

    public function testGetAttemptCountTimeWindow(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test', 'test.log');
        
        // Should find within 60 minutes
        $this->assertEquals(1, $this->db->getAttemptCount('1.1.1.1', 60));
        
        // Non-existent IP should return 0
        $this->assertEquals(0, $this->db->getAttemptCount('9.9.9.9', 60));
    }
}
