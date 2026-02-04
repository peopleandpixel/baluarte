<?php

namespace Baluarte\Tests\Database;

use PHPUnit\Framework\TestCase;
use Baluarte\Database\DatabaseHandler;

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
}
