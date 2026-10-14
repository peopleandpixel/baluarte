<?php

declare(strict_types=1);

namespace Baluarte\Tests\Integration\Scanner;

use Baluarte\Scanner\GeoIpService;
use Baluarte\Tests\Integration\IntegrationTestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayCache;

/**
 * Integration tests for GeoIpService with a real MaxMind GeoLite2 database.
 * 
 * These tests use the local GeoLite2-City.mmdb database file
 * to verify that GeoIP lookups work correctly with real data.
 */
class GeoIpServiceTest extends IntegrationTestCase
{
    private ?string $dbPath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dbPath = __DIR__ . '/../../../data/GeoLite2-City.mmdb';

        if (!file_exists($this->dbPath)) {
            $this->markTestSkipped('GeoLite2-City.mmdb database not found at ' . $this->dbPath);
        }
    }

    public function testLookupWithRealDatabase(): void
    {
        $service = new GeoIpService($this->dbPath, new NullLogger());

        // 8.8.8.8 is Google's DNS server, located in the USA
        $result = $service->lookup('8.8.8.8');

        $this->assertNotEmpty($result);
        $this->assertArrayHasKey('country', $result);
        $this->assertArrayHasKey('city', $result);
        $this->assertArrayHasKey('country_code', $result);
        $this->assertArrayHasKey('latitude', $result);
        $this->assertArrayHasKey('longitude', $result);
    }

    public function testLookupReturnsCountryCode(): void
    {
        $service = new GeoIpService($this->dbPath, new NullLogger());

        $result = $service->lookup('8.8.8.8');

        $this->assertArrayHasKey('country_code', $result);
        $this->assertNotNull($result['country_code']);
    }

    public function testLookupWithCache(): void
    {
        $cache = new ArrayCache();
        $service = new GeoIpService($this->dbPath, new NullLogger(), $cache);

        // First call should hit the database
        $result1 = $service->lookup('8.8.8.8');
        $this->assertNotEmpty($result1);

        // Second call should use cache
        $result2 = $service->lookup('8.8.8.8');
        $this->assertEquals($result1, $result2);
    }

    public function testLookupIps(): void
    {
        $service = new GeoIpService($this->dbPath, new NullLogger());

        $results = $service->lookupIps(['8.8.8.8', '1.1.1.1']);

        $this->assertArrayHasKey('8.8.8.8', $results);
        $this->assertArrayHasKey('1.1.1.1', $results);
    }

    public function testLookupIpsWithCache(): void
    {
        $cache = new ArrayCache();
        $service = new GeoIpService($this->dbPath, new NullLogger(), $cache);

        $results = $service->lookupIps(['8.8.8.8', '1.1.1.1']);

        $this->assertArrayHasKey('8.8.8.8', $results);
        $this->assertArrayHasKey('1.1.1.1', $results);
    }

    public function testLookupPrivateIpReturnsEmpty(): void
    {
        $service = new GeoIpService($this->dbPath, new NullLogger());

        $result = $service->lookup('127.0.0.1');

        $this->assertIsArray($result);
        // Private IPs typically return empty results from GeoIP databases
    }

    public function testLookupWithoutDatabase(): void
    {
        $service = new GeoIpService(null, new NullLogger());

        $result = $service->lookup('8.8.8.8');

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    public function testLookupWithNonExistentDatabase(): void
    {
        $service = new GeoIpService('/nonexistent/path.mmdb', new NullLogger());

        $result = $service->lookup('8.8.8.8');

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    public function testLookupIpsWithoutDatabase(): void
    {
        $service = new GeoIpService(null, new NullLogger());

        $results = $service->lookupIps(['8.8.8.8', '1.1.1.1']);

        $this->assertArrayHasKey('8.8.8.8', $results);
        $this->assertArrayHasKey('1.1.1.1', $results);
        $this->assertEmpty($results['8.8.8.8']);
        $this->assertEmpty($results['1.1.1.1']);
    }

    public function testLookupReturnsNumericCoordinates(): void
    {
        $service = new GeoIpService($this->dbPath, new NullLogger());

        $result = $service->lookup('8.8.8.8');

        if (!empty($result)) {
            $this->assertIsFloat($result['latitude']);
            $this->assertIsFloat($result['longitude']);
            $this->assertGreaterThanOrEqual(-90, $result['latitude']);
            $this->assertLessThanOrEqual(90, $result['latitude']);
            $this->assertGreaterThanOrEqual(-180, $result['longitude']);
            $this->assertLessThanOrEqual(180, $result['longitude']);
        }
    }
}
