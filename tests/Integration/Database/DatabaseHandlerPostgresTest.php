<?php

declare(strict_types=1);

namespace Baluarte\Tests\Integration\Database;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Tests\Integration\IntegrationTestCase;
use Testcontainers\Container\StartedGenericContainer;
use Testcontainers\Modules\PostgresContainer;

/**
 * Integration tests for DatabaseHandler with PostgreSQL.
 * 
 * These tests use a real PostgreSQL container via Testcontainers
 * to verify that all database operations work correctly with PostgreSQL.
 */
class DatabaseHandlerPostgresTest extends IntegrationTestCase
{
    private ?StartedGenericContainer $container = null;
    private DatabaseHandler $db;

    protected function getRequiredExtensions(): array
    {
        return ['pdo_pgsql'];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->container = (new PostgresContainer('17-alpine', 'test', 'test', 'baluarte'))->start();

        $dbConfig = [
            'driver' => 'postgresql',
            'host' => $this->container->getHost(),
            'port' => $this->container->getMappedPort(5432),
            'dbname' => 'baluarte',
            'user' => 'test',
            'password' => 'test',
        ];

        $this->db = new DatabaseHandler($dbConfig);
    }

    protected function tearDown(): void
    {
        if ($this->container !== null) {
            $this->container->stop();
        }
        parent::tearDown();
    }

    // --- Basic CRUD Tests ---

    public function testSaveAndGetIp(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test reason', 'test.log');

        $ips = $this->db->getAllDetectedIps();
        $this->assertContains('1.1.1.1', $ips);
    }

    public function testGetDetectedIpsCount(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test reason', 'test.log');
        $this->db->saveIp('2.2.2.2', 'Test reason', 'test.log');

        $count = $this->db->getDetectedIpsCount();
        $this->assertEquals(2, $count);
    }

    public function testGetAttemptCount(): void
    {
        $this->db->saveIp('1.1.1.1', 'Test reason', 'test.log');
        $this->db->saveIp('1.1.1.1', 'Test reason 2', 'test.log');

        $count = $this->db->getAttemptCount('1.1.1.1');
        $this->assertEquals(2, $count);
    }

    public function testGetAttemptCountUnknownIp(): void
    {
        $count = $this->db->getAttemptCount('9.9.9.9');
        $this->assertEquals(0, $count);
    }

    // --- Ban Tests ---

    public function testAddAndGetActiveBans(): void
    {
        $this->db->addBan('1.1.1.1', 3600, 'ip');

        $bans = $this->db->getActiveBans();
        $this->assertContains('1.1.1.1', $bans);
    }

    public function testAddBanWithType(): void
    {
        $this->db->addBan('1.1.1.1', 60, 'ip');
        $this->db->addBan('DE', 60, 'country');

        $ipBans = $this->db->getActiveBansByType('ip');
        $countryBans = $this->db->getActiveBansByType('country');

        $this->assertContains('1.1.1.1', $ipBans);
        $this->assertNotContains('DE', $ipBans);
        $this->assertContains('DE', $countryBans);
        $this->assertNotContains('1.1.1.1', $countryBans);
    }

    public function testGetActiveBansDetailed(): void
    {
        $this->db->addBan('1.1.1.1', 3600, 'ip');

        $detailed = $this->db->getActiveBansDetailed();
        $this->assertIsArray($detailed);
        $this->assertNotEmpty($detailed);
        $this->assertEquals('1.1.1.1', $detailed[0]['target']);
        $this->assertEquals('ip', $detailed[0]['type']);
    }

    public function testGetActiveBansCount(): void
    {
        $this->db->addBan('1.1.1.1', 60, 'ip');
        $this->db->addBan('2.2.2.2', 60, 'ip');
        $this->db->addBan('3.3.3.3', -1, 'ip'); // expired

        $count = $this->db->getActiveBansCount();
        $this->assertEquals(2, $count);
    }

    public function testRemoveBan(): void
    {
        $this->db->addBan('1.1.1.1', 3600, 'ip');
        $this->assertTrue($this->db->removeBan('1.1.1.1'));

        $bans = $this->db->getActiveBans();
        $this->assertNotContains('1.1.1.1', $bans);
    }

    public function testRemoveBanNotFound(): void
    {
        $this->assertFalse($this->db->removeBan('9.9.9.9'));
    }

    public function testGetExpiredBans(): void
    {
        $this->db->addBan('1.1.1.1', -1, 'ip'); // already expired

        $expired = $this->db->getExpiredBans();
        $this->assertContains('1.1.1.1', $expired);
    }

    public function testCleanup(): void
    {
        $this->db->addBan('1.1.1.1', -1, 'ip'); // expired

        $this->db->cleanup();

        $bans = $this->db->getActiveBans();
        $this->assertNotContains('1.1.1.1', $bans);
    }

    // --- Ban Details Tests ---

    public function testGetBanDetails(): void
    {
        $this->db->addBan('1.1.1.1', 3600, 'ip');

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

    // --- IP History Tests ---

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

    // --- Geo Data Tests ---

    public function testSaveIpWithGeoData(): void
    {
        $geoData = ['country' => 'Germany', 'city' => 'Berlin', 'isp' => 'Telekom'];
        $this->db->saveIp('1.1.1.1', 'Test', 'test.log', $geoData);

        $history = $this->db->getIpHistory('1.1.1.1');
        $this->assertCount(1, $history);
        $this->assertEquals('Germany', $history[0]['country']);
        $this->assertEquals('Berlin', $history[0]['city']);
        $this->assertEquals('Telekom', $history[0]['isp']);
    }

    // --- Settings Tests ---

    public function testGetAndSetSetting(): void
    {
        $this->db->setSetting('test_key', 'test_value');

        $value = $this->db->getSetting('test_key');
        $this->assertEquals('test_value', $value);
    }

    public function testGetSettingNotFound(): void
    {
        $value = $this->db->getSetting('nonexistent');
        $this->assertNull($value);
    }

    // --- Statistics Tests ---

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
        $this->assertCount(24, $timeline);
        foreach ($timeline as $entry) {
            $this->assertEquals(0, $entry['count']);
        }
    }

    // --- Save IPs batch test ---

    public function testSaveIpsBatch(): void
    {
        $ips = [
            ['ip' => '1.1.1.1', 'reason' => 'Test 1', 'logfile' => 'test.log'],
            ['ip' => '2.2.2.2', 'reason' => 'Test 2', 'logfile' => 'test.log'],
            ['ip' => '3.3.3.3', 'reason' => 'Test 3', 'logfile' => 'test.log'],
        ];

        $this->db->saveIps($ips);

        $count = $this->db->getDetectedIpsCount();
        $this->assertEquals(3, $count);
    }

    // --- Connection and Logger tests ---

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

    // --- Schema initialization test ---

    public function testSchemaInitialized(): void
    {
        $connection = $this->db->getConnection();
        $tables = $connection->createSchemaManager()->listTableNames();

        $this->assertContains('detected_ips', $tables);
        $this->assertContains('bans', $tables);
        $this->assertContains('settings', $tables);
        $this->assertContains('audit_log', $tables);
    }
}
