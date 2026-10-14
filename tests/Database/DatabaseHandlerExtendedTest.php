<?php

namespace Baluarte\Tests\Database;

use Baluarte\Database\DatabaseHandler;
use PHPUnit\Framework\TestCase;

class DatabaseHandlerExtendedTest extends TestCase
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

    public function testGetActiveBansByType(): void
    {
        $this->db->addBan('1.1.1.1', 60, 'ip');
        $this->db->addBan('2.2.2.2', 60, 'country');

        $ipBans = $this->db->getActiveBansByType('ip');
        $countryBans = $this->db->getActiveBansByType('country');

        $this->assertContains('1.1.1.1', $ipBans);
        $this->assertNotContains('2.2.2.2', $ipBans);
        $this->assertContains('2.2.2.2', $countryBans);
    }

    public function testGetActiveBansCount(): void
    {
        $this->db->addBan('1.1.1.1', 60, 'ip');
        $this->db->addBan('2.2.2.2', 60, 'ip');
        $this->db->addBan('3.3.3.3', -1, 'ip'); // expired

        $count = $this->db->getActiveBansCount();
        $this->assertEquals(2, $count);
    }

    public function testGetBanDetails(): void
    {
        $this->db->addBan('1.1.1.1', 60, 'ip');

        $details = $this->db->getBanDetails('1.1.1.1');
        $this->assertNotNull($details);
        $this->assertEquals('1.1.1.1', $details['target']);
        $this->assertEquals('ip', $details['type']);
    }

    public function testGetBanDetailsNotFound(): void
    {
        $details = $this->db->getBanDetails('9.9.9.9');
        $this->assertNull($details);
    }

    public function testGetIpHistory(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test Reason 1', 'test.log');
        $this->db->saveIp('1.1.1.1', 'Test Reason 2', 'test.log');

        $history = $this->db->getIpHistory('1.1.1.1');
        $this->assertCount(2, $history);
        $this->assertEquals('1.1.1.1', $history[0]['ip']);
    }

    public function testGetIpHistoryNotFound(): void
    {
        $history = $this->db->getIpHistory('9.9.9.9');
        $this->assertIsArray($history);
        $this->assertEmpty($history);
    }

    public function testGetThreatsByHour(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test', 'test.log');

        $threats = $this->db->getThreatsByHour();
        $this->assertIsArray($threats);
    }

    public function testGetThreatsByDay(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test', 'test.log');

        $threats = $this->db->getThreatsByDay();
        $this->assertIsArray($threats);
    }

    public function testGetThreatsByWeek(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test', 'test.log');

        $threats = $this->db->getThreatsByWeek();
        $this->assertIsArray($threats);
    }

    public function testGetTopCountries(): void
    {
        $geoData1 = ['country' => 'Germany', 'city' => 'Berlin', 'isp' => 'Telekom'];
        $geoData2 = ['country' => 'USA', 'city' => 'New York', 'isp' => 'Verizon'];

        $this->db->saveIp('1.1.1.1', 'Test', 'test.log', $geoData1);
        $this->db->saveIp('2.2.2.2', 'Test', 'test.log', $geoData1);
        $this->db->saveIp('3.3.3.3', 'Test', 'test.log', $geoData2);

        $countries = $this->db->getTopCountries(10);
        $this->assertIsArray($countries);
        $this->assertNotEmpty($countries);
    }

    public function testGetTopCountriesEmpty(): void
    {
        $countries = $this->db->getTopCountries(10);
        $this->assertIsArray($countries);
        $this->assertEmpty($countries);
    }

    public function testGetAttackTypes(): void
    {
        $this->db->saveIp('1.1.1.1', 'SSH failed login attempt', 'test.log');
        $this->db->saveIp('2.2.2.2', 'SQL injection attempt', 'test.log');

        $types = $this->db->getAttackTypes();
        $this->assertIsArray($types);
        $this->assertNotEmpty($types);
    }

    public function testGetAttackTypesEmpty(): void
    {
        $types = $this->db->getAttackTypes();
        $this->assertIsArray($types);
        $this->assertEmpty($types);
    }

    public function testGetBanTimeline(): void
    {
        $this->db->addBan('1.1.1.1', 60, 'ip');
        $this->db->addBan('2.2.2.2', 60, 'country');

        $timeline = $this->db->getBanTimeline();
        $this->assertIsArray($timeline);
    }

    public function testGetBanTimelineEmpty(): void
    {
        $timeline = $this->db->getBanTimeline();
        $this->assertIsArray($timeline);
        // getBanTimeline always returns 24 hours filled with zeros
        $this->assertCount(24, $timeline);
        // All counts should be zero when no bans exist
        foreach ($timeline as $entry) {
            $this->assertEquals(0, $entry['count']);
        }
    }

    public function testGetConnection(): void
    {
        $connection = $this->db->getConnection();
        $this->assertInstanceOf(\Doctrine\DBAL\Connection::class, $connection);
    }

    public function testGetLogger(): void
    {
        $logger = $this->db->getLogger();
        $this->assertInstanceOf(\Psr\Log\LoggerInterface::class, $logger);
    }
}
