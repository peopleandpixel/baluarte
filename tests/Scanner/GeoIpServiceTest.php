<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\GeoIpService;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class GeoIpServiceTest extends TestCase
{
    public function testLookupReturnsEmptyWithoutDatabase(): void
    {
        $service = new GeoIpService();
        $result = $service->lookup('192.168.1.1');

        $this->assertEquals([], $result);
    }

    public function testLookupReturnsEmptyWithNonExistentDatabase(): void
    {
        $logger = $this->createStub(LoggerInterface::class);

        // When file doesn't exist, reader is not initialized, so lookup returns empty
        $service = new GeoIpService('/nonexistent/path.mmdb', $logger);
        $result = $service->lookup('192.168.1.1');

        $this->assertEquals([], $result);
    }

    public function testLookupIpsReturnsEmptyWithoutDatabase(): void
    {
        $service = new GeoIpService();
        $result = $service->lookupIps(['192.168.1.1', '10.0.0.1']);

        $this->assertEquals([
            '192.168.1.1' => [],
            '10.0.0.1' => [],
        ], $result);
    }

    public function testConstructorWithNullLogger(): void
    {
        // Should not throw
        $service = new GeoIpService(null, null, null);
        $this->assertInstanceOf(GeoIpService::class, $service);
    }

    public function testConstructorWithCache(): void
    {
        $cache = new ArrayAdapter();
        $service = new GeoIpService(null, null, $cache);
        $this->assertInstanceOf(GeoIpService::class, $service);
    }
}
