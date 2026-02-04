<?php

namespace Baluarte\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use Baluarte\Scanner\DnsblService;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class DnsblServiceTest extends TestCase
{
    public function testCheckIpReturnsEmptyIfNoDnsbls(): void
    {
        $service = new DnsblService([]);
        $this->assertEquals([], $service->checkIp('127.0.0.1'));
    }

    public function testCheckIpReturnsEmptyForIpv6(): void
    {
        $service = new DnsblService(['zen.spamhaus.org']);
        $this->assertEquals([], $service->checkIp('2001:db8::1'));
    }

    public function testCheckIps(): void
    {
        $service = new DnsblService([]);
        $results = $service->checkIps(['127.0.0.1', '8.8.8.8']);
        $this->assertArrayHasKey('127.0.0.1', $results);
        $this->assertArrayHasKey('8.8.8.8', $results);
    }

    public function testCacheIsUsed(): void
    {
        $cache = new ArrayAdapter();
        // Use a non-existent DNSBL to avoid actual network calls if possible, 
        // but gethostbyname will still be called.
        // We'll mock the service to avoid network calls entirely.
        
        $service = $this->getMockBuilder(DnsblService::class)
            ->setConstructorArgs([['test.dnsbl'], $cache])
            ->onlyMethods(['doCheckIp'])
            ->getMock();

        $service->expects($this->once())
            ->method('doCheckIp')
            ->with('1.2.3.4')
            ->willReturn(['test.dnsbl']);

        // First call should trigger doCheckIp
        $result1 = $service->checkIp('1.2.3.4');
        $this->assertEquals(['test.dnsbl'], $result1);

        // Second call should come from cache
        $result2 = $service->checkIp('1.2.3.4');
        $this->assertEquals(['test.dnsbl'], $result2);
    }
}
