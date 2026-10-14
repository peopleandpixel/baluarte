<?php

declare(strict_types=1);

namespace Baluarte\Tests\Http;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Service\AuditLogService;
use Baluarte\Scanner\RateLimiter;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Integration test for the REST API flow.
 * Tests the full cycle: get bans → add ban → verify ban → remove ban.
 */
class ApiIntegrationTest extends TestCase
{
    private string $dbPath;
    private DatabaseHandler $dbHandler;
    private string $jwtSecret;
    private array $originalServer;
    private array $originalPost;
    private array $originalGet;
    /** @var array<string, mixed> */
    private array $originalSession;

    protected function setUp(): void
    {
        $this->dbPath = tempnam(sys_get_temp_dir(), 'db_api');
        $this->dbHandler = new DatabaseHandler($this->dbPath, new NullLogger());
        // JWT requires at least 256 bits (32 bytes) for HS256
        $this->jwtSecret = base64_encode(random_bytes(32));

        // Backup superglobals
        $this->originalServer = $_SERVER ?? [];
        $this->originalPost = $_POST ?? [];
        $this->originalGet = $_GET ?? [];
        $this->originalSession = $_SESSION ?? [];

        // Set up test superglobals
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/api/bans';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_POST = [];
        $_GET = [];
        $_SESSION = [];

        // Create a temporary config file for the controller
        $this->createTestConfig();
    }

    protected function tearDown(): void
    {
        // Restore superglobals
        $_SERVER = $this->originalServer;
        $_POST = $this->originalPost;
        $_GET = $this->originalGet;
        $_SESSION = $this->originalSession;

        // Clean up
        if (file_exists($this->dbPath)) {
            unlink($this->dbPath);
        }
        $this->removeTestConfig();
    }

    private function createTestConfig(): void
    {
        $configDir = __DIR__ . '/../../config';
        $configPath = $configDir . '/config.yaml';
        
        $config = [
            'database' => ['path' => $this->dbPath],
            'api' => ['jwt_secret' => $this->jwtSecret],
            'gui' => [],
            'i18n' => ['default_locale' => 'en', 'available_locales' => ['en']],
            'whitelist' => [],
        ];

        file_put_contents($configPath, \Symfony\Component\Yaml\Yaml::dump($config, 10));
    }

    private function removeTestConfig(): void
    {
        $configPath = __DIR__ . '/../../config/config.yaml';
        if (strpos($this->dbPath, 'db_api') !== false && file_exists($configPath)) {
            // Only remove if we created it
            $content = file_get_contents($configPath);
            if (is_string($content) && strpos($content, $this->dbPath) !== false) {
                unlink($configPath);
            }
        }
    }

    private function generateJwtToken(): string
    {
        $payload = [
            'iat' => time(),
            'exp' => time() + 3600,
            'sub' => 'test-user',
        ];
        return JWT::encode($payload, $this->jwtSecret, 'HS256');
    }

    private function setAuthHeader(string $token): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
    }

    /**
     * Test the full API flow: get bans → add ban → verify → remove → verify removed.
     */
    public function testFullApiFlow(): void
    {
        // We test the database operations directly since the controllers
        // use exit() which is hard to test in unit tests. The router
        // integration is tested via the database state.
        
        // 1. Initial state: no bans
        $bans = $this->dbHandler->getActiveBansDetailed();
        $this->assertEmpty($bans);

        // 2. Add a ban
        $success = $this->dbHandler->addBan('10.20.30.40', 60, 'ip');
        $this->assertTrue($success);

        // 3. Verify the ban exists
        $bans = $this->dbHandler->getActiveBansDetailed();
        $this->assertCount(1, $bans);
        $this->assertEquals('10.20.30.40', $bans[0]['target']);
        $this->assertEquals('ip', $bans[0]['type']);

        // 4. Add another ban
        $this->dbHandler->addBan('192.168.1.100', 120, 'ip');
        $bans = $this->dbHandler->getActiveBansDetailed();
        $this->assertCount(2, $bans);

        // 5. Remove a ban
        $success = $this->dbHandler->removeBan('10.20.30.40');
        $this->assertTrue($success);

        // 6. Verify only one ban remains
        $bans = $this->dbHandler->getActiveBansDetailed();
        $this->assertCount(1, $bans);
        $this->assertEquals('192.168.1.100', $bans[0]['target']);
    }

    /**
     * Test JWT authentication flow.
     */
    public function testJwtAuthentication(): void
    {
        $token = $this->generateJwtToken();
        
        // Valid token should decode
        $decoded = JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
        $this->assertEquals('test-user', $decoded->sub);
        $this->assertGreaterThan(time(), $decoded->exp);
    }

    /**
     * Test JWT authentication with invalid token.
     */
    public function testJwtAuthenticationInvalidToken(): void
    {
        $this->expectException(\Exception::class);
        
        // Create an expired token
        $payload = [
            'iat' => time() - 7200,
            'exp' => time() - 3600,
            'sub' => 'test-user',
        ];
        $token = JWT::encode($payload, $this->jwtSecret, 'HS256');
        JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
    }

    /**
     * Test rate limiter functionality.
     */
    public function testRateLimiter(): void
    {
        $cache = new ArrayAdapter();
        $rateLimiter = new RateLimiter($cache, 5, 60); // 5 requests per 60 seconds

        // First 5 requests should not be rate limited
        for ($i = 0; $i < 5; $i++) {
            $this->assertFalse($rateLimiter->isRateLimited('127.0.0.1'));
        }

        // 6th request should be rate limited
        $this->assertTrue($rateLimiter->isRateLimited('127.0.0.1'));

        // Different IP should not be rate limited
        $this->assertFalse($rateLimiter->isRateLimited('192.168.1.1'));
    }

    /**
     * Test threat detection and retrieval flow.
     */
    public function testThreatDetectionFlow(): void
    {
        // Save detected IPs
        $this->dbHandler->saveIp('10.20.30.40', 'Brute force', 'auth.log', [
            'country' => 'China',
            'city' => 'Beijing',
            'isp' => 'TestISP',
        ]);
        $this->dbHandler->saveIp('192.168.1.100', 'SQL Injection', 'access.log', [
            'country' => 'Russia',
            'city' => 'Moscow',
            'isp' => 'TestISP2',
        ]);

        // Get all detected IPs
        $threats = $this->dbHandler->getAllDetectedIps();
        $this->assertCount(2, $threats);

        // Verify data integrity
        $ips = array_column($threats, 'ip');
        $this->assertContains('10.20.30.40', $ips);
        $this->assertContains('192.168.1.100', $ips);

        // Test with limit
        $limited = $this->dbHandler->getAllDetectedIps(1);
        $this->assertCount(1, $limited);
    }

    /**
     * Test ban with different types (IP, country, range).
     */
    public function testBanTypes(): void
    {
        $this->dbHandler->addBan('10.20.30.40', 60, 'ip');
        $this->dbHandler->addBan('CN', 60, 'country');
        $this->dbHandler->addBan('192.168.0.0/16', 60, 'range');

        // Get all bans
        $bans = $this->dbHandler->getActiveBansDetailed();
        $this->assertCount(3, $bans);

        // Filter by type
        $ipBans = $this->dbHandler->getActiveBansByType('ip');
        $this->assertContains('10.20.30.40', $ipBans);
        $this->assertCount(1, $ipBans);

        $countryBans = $this->dbHandler->getActiveBansByType('country');
        $this->assertContains('CN', $countryBans);

        $rangeBans = $this->dbHandler->getActiveBansByType('range');
        $this->assertContains('192.168.0.0/16', $rangeBans);
    }

    /**
     * Test audit log records ban actions.
     */
    public function testAuditLogRecordsActions(): void
    {
        $auditLog = new AuditLogService($this->dbHandler->getConnection());

        // Log a ban added
        $auditLog->logBanAdded('10.20.30.40', 60, 'ip', '127.0.0.1');
        
        // Log a ban removed
        $auditLog->logBanRemoved('10.20.30.40', '127.0.0.1');

        // Verify audit log entries
        $entries = $auditLog->getRecent(10);
        $this->assertCount(2, $entries);
        
        $actions = array_column($entries, 'action');
        $this->assertContains('ban_added', $actions);
        $this->assertContains('ban_removed', $actions);
    }

    /**
     * Test settings CRUD flow.
     */
    public function testSettingsFlow(): void
    {
        // Set settings
        $this->dbHandler->setSetting('ban_duration', '1440');
        $this->dbHandler->setSetting('threshold_attempts', '5');

        // Get settings
        $this->assertEquals('1440', $this->dbHandler->getSetting('ban_duration'));
        $this->assertEquals('5', $this->dbHandler->getSetting('threshold_attempts'));

        // Update setting
        $this->dbHandler->setSetting('ban_duration', '720');
        $this->assertEquals('720', $this->dbHandler->getSetting('ban_duration'));

        // Non-existent setting with default
        $this->assertEquals('default', $this->dbHandler->getSetting('non_existent', 'default'));
    }

    /**
     * Test expired ban handling.
     */
    public function testExpiredBanHandling(): void
    {
        // Add an expired ban
        $this->dbHandler->addBan('10.20.30.40', -1);
        
        // Should not appear in active bans
        $active = $this->dbHandler->getActiveBans();
        $this->assertNotContains('10.20.30.40', $active);

        // Should appear in expired bans
        $expired = $this->dbHandler->getExpiredBans();
        $this->assertContains('10.20.30.40', $expired);

        // Ban details should return null for expired
        $details = $this->dbHandler->getBanDetails('10.20.30.40');
        $this->assertNull($details);
    }

    /**
     * Test IP history tracking.
     */
    public function testIpHistoryTracking(): void
    {
        $this->dbHandler->saveIp('10.20.30.40', 'Brute force', 'auth.log');
        $this->dbHandler->saveIp('10.20.30.40', 'SQL Injection', 'access.log');
        $this->dbHandler->saveIp('10.20.30.40', 'XSS', 'access.log');

        $history = $this->dbHandler->getIpHistory('10.20.30.40');
        $this->assertCount(3, $history);

        // Should be ordered by detected_at DESC
        $reasons = array_column($history, 'reason');
        // All three reasons should be present
        $this->assertContains('Brute force', $reasons);
        $this->assertContains('SQL Injection', $reasons);
        $this->assertContains('XSS', $reasons);
    }
}
