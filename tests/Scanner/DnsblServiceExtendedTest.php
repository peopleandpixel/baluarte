<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\DnsblService;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class DnsblServiceExtendedTest extends TestCase
{
    public function testCheckIpReturnsEmptyWithoutDnsbls(): void
    {
        $service = new DnsblService([]);
        $result = $service->checkIp('192.168.1.1');

        $this->assertEquals([], $result);
    }

    public function testCheckIpReturnsEmptyForIpv6(): void
    {
        $service = new DnsblService(['zen.spamhaus.org']);
        $result = $service->checkIp('2001:db8::1');

        $this->assertEquals([], $result);
    }

    public function testCheckIpsReturnsResultsForMultipleIps(): void
    {
        $service = new DnsblService([]);
        $result = $service->checkIps(['192.168.1.1', '10.0.0.1']);

        $this->assertArrayHasKey('192.168.1.1', $result);
        $this->assertArrayHasKey('10.0.0.1', $result);
    }

    public function testConstructorWithCache(): void
    {
        $cache = new ArrayAdapter();
        $service = new DnsblService(['zen.spamhaus.org'], $cache);
        $this->assertInstanceOf(DnsblService::class, $service);
    }

    public function testConstructorWithEmptyDnsbls(): void
    {
        $service = new DnsblService();
        $this->assertInstanceOf(DnsblService::class, $service);
    }
}
